/**
 * @file ConsoleUI.cpp
 * @brief Full-screen box-drawing TUI for PPP PRIVATE NETWORK(TM) 2.
 *
 * @details
 * Implements a double-buffered, box-drawing terminal UI with three scrollable
 * sections (info, command output, and a single-line editor), rendered at up
 * to 10 Hz by a dedicated render thread.  A separate input thread handles
 * keyboard events without blocking the Boost.ASIO event loop.
 *
 * Key bindings:
 *   PageUp / PageDown  — scroll the command output section
 *   Home / End         — scroll the VPN info section
 *   Up / Down arrow    — navigate command history
 *   Left / Right arrow — move text cursor
 *   Ctrl+A             — move cursor to start of line
 *   Ctrl+E             — move cursor to end of line
 *   Backspace / Del    — erase character
 *   Enter              — execute command
 */

#include <ppp/app/ConsoleUI.h>
#include <ppp/app/PppApplication.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/app/tui/TuiRuntimeAdapter.h>
#include <ppp/threading/Executors.h>

#include <cstdlib>

#if defined(_WIN32)
#   include <conio.h>
#   include <io.h>
#else
#   include <cerrno>
#   include <fcntl.h>
#   include <poll.h>
#   include <unistd.h>
#endif

namespace ppp::app {

// ---------------------------------------------------------------------------
// TUI-aware telemetry sink — redirects telemetry stderr output into the
// ConsoleUI event ring buffer when the TUI is active.
// ---------------------------------------------------------------------------

/**
 * @brief Console sink callback installed into the telemetry backend.
 *
 * Called from the TelemetryBackend worker thread for every formatted
 * telemetry line that would otherwise be written to stderr.
 */
static void TelemetryToConsoleUI(const char* line) noexcept {
    // The telemetry backend loads the sink function pointer without taking the
    // ConsoleUI lifecycle lock.  Stop() clears running_ before unregistering the
    // sink, so this guard closes the small race where a backend worker may have
    // already loaded this callback while the TUI is tearing down.
    if (!ConsoleUI::IsRunning()) {
        return;
    }

    ConsoleUI::GetInstance().AppendTelemetryEventLine(line);
}

/**
 * @brief Strips ANSI escape sequences from a string.
 *
 * Removes all occurrences of ESC[...m (SGR) sequences so that the
 * resulting string contains only printable characters suitable for
 * FitWidth() display-width calculation.
 */
static ppp::string StripAnsiEscapes(const ppp::string& s) noexcept {
    ppp::string result;
    result.reserve(s.size());
    bool in_escape = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (in_escape) {
            if (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')) {
                in_escape = false;
            }
        } else if (c == '\x1b') {
            in_escape = true;
        } else {
            result.push_back(c);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// UTF-8 box-drawing character constants (each is 3 bytes, 1 display column)
// ---------------------------------------------------------------------------

/** @brief Top-left corner:   ┌ (U+250C) */
static constexpr const char kBL[]   = "\xe2\x94\x8c";
/** @brief Top-right corner:  ┐ (U+2510) */
static constexpr const char kBR[]   = "\xe2\x94\x90";
/** @brief Bottom-left:       └ (U+2514) */
static constexpr const char kBBL[]  = "\xe2\x94\x94";
/** @brief Bottom-right:      ┘ (U+2518) */
static constexpr const char kBBR[]  = "\xe2\x94\x98";
/** @brief Left-T junction:   ├ (U+251C) */
static constexpr const char kLT[]   = "\xe2\x94\x9c";
/** @brief Right-T junction:  ┤ (U+2524) */
static constexpr const char kRT[]   = "\xe2\x94\xa4";
/** @brief Top-T junction:    ┬ (U+252C) */
static constexpr const char kTT[]   = "\xe2\x94\xac";
/** @brief Bottom-T junction: ┴ (U+2534) */
static constexpr const char kBT[]   = "\xe2\x94\xb4";
/** @brief Horizontal line:   ─ (U+2500) */
static constexpr const char kHH[]   = "\xe2\x94\x80";
/** @brief Vertical line:     │ (U+2502) */
static constexpr const char kVV[]   = "\xe2\x94\x82";

static bool g_use_unicode_ui_glyphs = true;

static bool IsEnvEnabled(const char* name) noexcept {
    const char* value = std::getenv(name);
    if (NULLPTR == value || '\0' == value[0]) {
        return false;
    }

    char first = value[0];
    return first != '0' && first != 'n' && first != 'N' && first != 'f' && first != 'F';
}

static bool SelectUnicodeUiGlyphs() noexcept {
    if (IsEnvEnabled("PPP_TUI_ASCII")) {
        return false;
    }
    if (IsEnvEnabled("PPP_TUI_UTF8")) {
        return true;
    }

#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

static bool UseUnicodeUiGlyphs() noexcept {
    return g_use_unicode_ui_glyphs;
}

static const char* BoxBL() noexcept { return UseUnicodeUiGlyphs() ? kBL  : "+"; }
static const char* BoxBR() noexcept { return UseUnicodeUiGlyphs() ? kBR  : "+"; }
static const char* BoxBBL() noexcept { return UseUnicodeUiGlyphs() ? kBBL : "+"; }
static const char* BoxBBR() noexcept { return UseUnicodeUiGlyphs() ? kBBR : "+"; }
static const char* BoxLT() noexcept { return UseUnicodeUiGlyphs() ? kLT  : "+"; }
static const char* BoxRT() noexcept { return UseUnicodeUiGlyphs() ? kRT  : "+"; }
static const char* BoxTT() noexcept { return UseUnicodeUiGlyphs() ? kTT  : "+"; }
static const char* BoxBT() noexcept { return UseUnicodeUiGlyphs() ? kBT  : "+"; }
static const char* BoxHH() noexcept { return UseUnicodeUiGlyphs() ? kHH  : "-"; }
static const char* BoxVV() noexcept { return UseUnicodeUiGlyphs() ? kVV  : "|"; }

// ---------------------------------------------------------------------------
// ANSI escape sequences
// ---------------------------------------------------------------------------

/** @brief Clear entire screen and move cursor to (1,1). */
static constexpr const char kClearScreen[] = "\x1b[2J\x1b[H";
/** @brief ANSI dark-gray foreground (for OPEN in art). */
static constexpr const char kColorGray[]   = "\x1b[90m";
/** @brief ANSI bold bright-white foreground (for PPP2 in art). */
static constexpr const char kColorWhite[]  = "\x1b[1;97m";
/** @brief ANSI dim gray foreground for TRACE diagnostics. */
static constexpr const char kColorTrace[]  = "\x1b[2;37m";
/** @brief ANSI cyan foreground for DEBUG diagnostics. */
static constexpr const char kColorDebug[]  = "\x1b[36m";
/** @brief ANSI green foreground for INFO diagnostics. */
static constexpr const char kColorInfo[]   = "\x1b[32m";
/** @brief ANSI yellow foreground for WARN diagnostics. */
static constexpr const char kColorWarn[]   = "\x1b[33m";
/** @brief ANSI red foreground for ERROR diagnostics. */
static constexpr const char kColorError[]  = "\x1b[31m";
/** @brief ANSI bright red foreground for FATAL diagnostics. */
static constexpr const char kColorFatal[]  = "\x1b[1;31m";
/** @brief ANSI attribute reset. */
static constexpr const char kColorReset[]  = "\x1b[0m";
/** @brief ANSI dim/dark gray (for placeholder text). */
static constexpr const char kColorDim[]    = "\x1b[2;37m";
/** @brief ANSI white background (used for the synthetic white-block cursor). */
static constexpr const char kColorWhiteBg[] = "\x1b[47m";
/** @brief Enter alternate screen buffer (preserves the user's original console contents). */
static constexpr const char kAltScreenOn[]  = "\x1b[?1049h";
/** @brief Leave alternate screen buffer (restores the user's original console contents). */
static constexpr const char kAltScreenOff[] = "\x1b[?1049l";
/** @brief Move cursor to top-left without clearing the screen. */
static constexpr const char kCursorHome[]   = "\x1b[H";

// ---------------------------------------------------------------------------
// ASCII art definition (5 lines, ~50 columns wide)
// ---------------------------------------------------------------------------

/**
 * @brief Five-line ASCII art for "OPENPPP2".
 *
 * Characters in display columns [0, kArtSplitCol) represent "OPEN" and are
 * rendered in dark gray.  The remainder represents "PPP2" in bright white.
 */
static constexpr const char* kArtLines[5] = {
    "  ___  ____  _____ _   _ ____  ____  ____ ____  ",
    " / _ \\|  _ \\| ____| \\ | |  _ \\|  _ \\|  _ \\___ \\ ",
    "| | | | |_) |  _| |  \\| | |_) | |_) | |_) |__) |",
    "| |_| |  __/| |___| |\\  |  __/|  __/|  __// __/ ",
    " \\___/|_|   |_____|_| \\_|_|   |_|   |_|  |_____|",
};

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

ConsoleUI& ConsoleUI::GetInstance() noexcept {
    static ConsoleUI instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Static helpers — box row builders
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::RepeatHoriz(int count) noexcept {
    if (0 >= count) {
        return ppp::string();
    }

    ppp::string s;
    s.reserve(static_cast<std::size_t>(count) * 3u);
    for (int i = 0; i < count; ++i) {
        s += BoxHH();
    }
    return s;
}

ppp::string ConsoleUI::FitWidth(const ppp::string& s, int display_width) noexcept {
    if (0 >= display_width) {
        return ppp::string();
    }

    std::size_t w = static_cast<std::size_t>(display_width);
    if (s.size() <= w) {
        ppp::string out = s;
        out.append(w - s.size(), ' ');
        return out;
    }

    if (4u > w) {
        return s.substr(0u, w);
    }

    return s.substr(0u, w - 3u) + "...";
}

ppp::string ConsoleUI::BoxContentRow(const ppp::string& content, int width) noexcept {
    if (2 > width) {
        return ppp::string();
    }

    int inner = width - 2;
    // Reserve one column before the right border so the box interior
    // never appears flush against the │ wall.
    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(inner) + 3u + 1u);
    row += BoxVV();
    row += FitWidth(content, inner - 1);
    row += " ";
    row += BoxVV();
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxSplitRow(
    const ppp::string& left,
    const ppp::string& right,
    int width,
    int split) noexcept {

    if (3 > width || 1 > split || split >= width - 2) {
        return BoxContentRow(left + " " + right, width);
    }

    // Left panel:  split-1 columns  (between left │ and center │)
    // Right panel: width-split-2 columns (between center │ and right │)
    // The center │ itself occupies 1 column inside the inner area.
    // Total = 1 + (split-1) + 1 + (width-split-2) + 1 = width
    int left_inner  = split - 1;
    int right_inner = width - split - 2;

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(left_inner)
              + 3u + static_cast<std::size_t>(right_inner)
              + 3u + 1u);
    row += BoxVV();
    row += FitWidth(left, left_inner);
    row += BoxVV();
    row += FitWidth(right, right_inner);
    row += BoxVV();
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxSepRow(int width) noexcept {
    if (2 > width) {
        return ppp::string();
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(width - 2) * 3u + 3u + 1u);
    row += BoxLT();
    row += RepeatHoriz(width - 2);
    row += BoxRT();
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxSplitSepRow(int width, int split) noexcept {
    if (3 > width || 1 > split || split >= width - 2) {
        return BoxSepRow(width);
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(split - 1) * 3u
              + 3u + static_cast<std::size_t>(width - split - 2) * 3u
              + 3u + 1u);
    row += BoxLT();
    row += RepeatHoriz(split - 1);
    row += BoxTT();
    row += RepeatHoriz(width - split - 2);
    row += BoxRT();
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxBotRow(int width) noexcept {
    if (2 > width) {
        return ppp::string();
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(width - 2) * 3u + 3u + 1u);
    row += BoxBBL();
    row += RepeatHoriz(width - 2);
    row += BoxBBR();
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxBotSplitRow(int width, int split) noexcept {
    if (3 > width || 1 > split || split >= width - 2) {
        return BoxBotRow(width);
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(split - 1) * 3u
              + 3u + static_cast<std::size_t>(width - split - 2) * 3u
              + 3u + 1u);
    row += BoxBBL();
    row += RepeatHoriz(split - 1);
    row += BoxBT();
    row += RepeatHoriz(width - split - 2);
    row += BoxBBR();
    row += "\n";
    return row;
}

// ---------------------------------------------------------------------------
// Art line renderer
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::RenderArtLine(
    const ppp::string& raw,
    int inner_width,
    bool use_color) noexcept {

    int art_len = static_cast<int>(raw.size());

    // Determine centering padding
    int padding = 0;
    if (art_len < inner_width) {
        padding = (inner_width - art_len) / 2;
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(inner_width + 1) * 8u);
    row += BoxVV();  // left border

    // Left padding
    if (0 < padding) {
        row.append(static_cast<std::size_t>(padding), ' ');
    }

    if (!use_color) {
        // Plain text — just copy the art line (clipped to available width)
        int avail = inner_width - padding;
        if (0 < avail) {
            int take = std::min(avail, art_len);
            row.append(raw.data(), static_cast<std::size_t>(take));
            int fill = avail - take;
            if (0 < fill) {
                row.append(static_cast<std::size_t>(fill), ' ');
            }
        }
    } else {
        // Colored art: OPEN (dark gray) / PPP2 (bright white)
        int avail     = inner_width - padding;
        int split_col = ConsoleUI::kArtSplitCol;

        // OPEN part (dark gray)
        int open_end  = std::min(split_col, art_len);
        int open_take = std::min(open_end, avail);
        if (0 < open_take) {
            row += kColorGray;
            row.append(raw.data(), static_cast<std::size_t>(open_take));
        }

        // PPP2 part (bright white)
        int ppp2_start = open_end;
        int ppp2_end   = art_len;
        int ppp2_avail = avail - open_take;
        int ppp2_take  = std::min(ppp2_end - ppp2_start, ppp2_avail);
        if (0 < ppp2_take && ppp2_start < art_len) {
            row += kColorWhite;
            row.append(raw.data() + ppp2_start, static_cast<std::size_t>(ppp2_take));
        }

        if (0 < open_take || 0 < ppp2_take) {
            row += kColorReset;
        }

        // Right padding within art area
        int used = open_take + ppp2_take;
        int fill = avail - used;
        if (0 < fill) {
            row.append(static_cast<std::size_t>(fill), ' ');
        }
    }

    row += BoxVV();  // right border
    row += "\n";
    return row;
}

// ---------------------------------------------------------------------------
// Editor-line builder
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::BuildEditorLine(
    const ppp::string& prompt,
    const ppp::string& input,
    std::size_t cursor_pos,
    int width,
    bool use_color,
    int& cursor_column) noexcept {

    cursor_column = 0;
    if (0 >= width) {
        return ppp::string();
    }

    std::size_t max_w = static_cast<std::size_t>(width);

    // Clip prompt to max_w
    ppp::string safe_prompt = prompt;
    if (safe_prompt.size() > max_w) {
        safe_prompt = safe_prompt.substr(0u, max_w);
    }

    std::size_t prompt_len = safe_prompt.size();
    std::size_t avail = (max_w > prompt_len) ? (max_w - prompt_len) : 0u;

    // Compute view window (scroll the editor text horizontally so the
    // caret is always visible inside 'avail' columns).
    std::size_t safe_cursor = std::min(cursor_pos, input.size());
    std::size_t view_start = 0u;
    if (0u < avail && safe_cursor >= avail) {
        view_start = safe_cursor - avail + 1u;
    }

    if (0u < avail && view_start + avail > input.size() && input.size() > avail) {
        view_start = input.size() - avail;
    }

    // Extract visible portion into a mutable byte buffer
    ppp::string view;
    if (0u < avail && view_start < input.size()) {
        std::size_t take = std::min(avail, input.size() - view_start);
        view = input.substr(view_start, take);
    }

    // Pad to exactly avail columns with spaces (cursor may land on a space)
    if (view.size() < avail) {
        view.append(avail - view.size(), ' ');
    }

    // Overflow indicators
    if (0u < view_start && !view.empty()) {
        view[0u] = '<';
    }
    if (view_start + avail < input.size() && !view.empty()) {
        view[avail - 1u] = '>';
    }

    // Compute cursor column relative to the visible window
    std::size_t local_cursor = (safe_cursor >= view_start) ? (safe_cursor - view_start) : 0u;
    if (0u < avail && avail <= local_cursor) {
        local_cursor = avail - 1u;
    }

    std::size_t col = prompt_len + local_cursor;
    if (0u < max_w && max_w <= col) {
        col = max_w - 1u;
    }
    cursor_column = static_cast<int>(col);

    // -----------------------------------------------------------------------
    // Assemble the final line.  When colour is available we embed a single
    // reverse-video (white-block) character at the cursor position so the
    // real terminal cursor can stay permanently hidden.  This removes all
    // cursor flicker that would otherwise arise from cyclic show/hide
    // escape sequences on every frame.
    // -----------------------------------------------------------------------
    ppp::string line;
    line.reserve(max_w + 16u);
    line += safe_prompt;

    if (use_color && 0u < avail) {
        std::size_t caret = local_cursor;
        if (avail <= caret) {
            caret = avail - 1u;
        }

        // Portion before the caret
        if (0u < caret) {
            line.append(view.data(), caret);
        }

        // Caret cell rendered as a white-background block.  We use an
        // explicit white background (\x1b[47m) instead of reverse video
        // (\x1b[7m) so the block appears as solid white irrespective of
        // the terminal's default colour scheme (dark vs light background).
        // The character underneath remains visible in black (the default
        // foreground colour after \x1b[0m), or is a space on empty input.
        line += kColorWhiteBg;
        char caret_ch = (caret < view.size()) ? view[caret] : ' ';
        if ('\0' == caret_ch || static_cast<unsigned char>(caret_ch) < 0x20) {
            caret_ch = ' ';
        }
        line.push_back(caret_ch);
        line += kColorReset;

        // Portion after the caret
        if (caret + 1u < view.size()) {
            line.append(view.data() + caret + 1u, view.size() - caret - 1u);
        }
    } else {
        line += view;
    }

    // Pad the trailing columns with plain spaces so the row keeps its
    // exact width inside the box border.
    // Note: line may now contain ANSI bytes; we cannot rely on size().
    // Instead, we computed 'avail' above and wrote prompt + avail
    // printable columns.  Any remaining visible gap is handled by the
    // caller which sizes the content via the box row builder.
    return line;
}

// ---------------------------------------------------------------------------
// Age formatter
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::FormatAge(uint64_t now_ms, uint64_t then_ms) noexcept {
    if (0u == then_ms || then_ms > now_ms) {
        return "n/a";
    }

    uint64_t delta_s = (now_ms - then_ms) / 1000u;
    return stl::to_string<ppp::string>(delta_s) + "s ago";
}

// ---------------------------------------------------------------------------
// ShouldEnable
// ---------------------------------------------------------------------------

bool ConsoleUI::ShouldEnable() noexcept {
    if (IsEnvEnabled("PPP_NO_TUI")) {
        return false;
    }

#if defined(_WIN32)
    return 0 != ::_isatty(::_fileno(stdout));
#else
    return 0 != ::isatty(STDOUT_FILENO);
#endif
}

// ---------------------------------------------------------------------------
// Start / Stop
// ---------------------------------------------------------------------------

bool ConsoleUI::Start() noexcept {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return true;  // already running
    }

    g_use_unicode_ui_glyphs = SelectUnicodeUiGlyphs();

    // -----------------------------------------------------------------------
    // Save the current console state so Stop() can restore it verbatim.
    // On Windows we snapshot the output mode and cursor visibility; on POSIX
    // the alternate-screen escape sequence handles full buffer restoration.
    // -----------------------------------------------------------------------
#if defined(_WIN32)
    win_stdout_handle_  = ::GetStdHandle(STD_OUTPUT_HANDLE);
    win_out_mode_saved_ = false;
    win_cursor_saved_   = false;
    win_output_cp_saved_ = false;

    // Save the current console output code page before EnableVirtualTerminal()
    // may switch it to UTF-8 when Unicode UI glyphs are explicitly enabled.
    win_original_output_cp_ = ::GetConsoleOutputCP();
    win_output_cp_saved_    = true;

    if (NULLPTR != win_stdout_handle_ && INVALID_HANDLE_VALUE != win_stdout_handle_) {
        DWORD mode = 0;
        if (::GetConsoleMode(static_cast<HANDLE>(win_stdout_handle_), &mode)) {
            win_original_out_mode_ = mode;
            win_out_mode_saved_    = true;
        }

        CONSOLE_CURSOR_INFO cci{};
        if (::GetConsoleCursorInfo(static_cast<HANDLE>(win_stdout_handle_), &cci)) {
            win_cursor_visible_ = (FALSE != cci.bVisible);
            win_cursor_saved_   = true;
        }
    }
#endif

    vt_enabled_ = EnableVirtualTerminal();

    if (!PrepareInputTerminal()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeOptionalUiStartFailed);
        running_.store(false, std::memory_order_release);
#if defined(_WIN32)
        if (NULLPTR != win_stdout_handle_ && INVALID_HANDLE_VALUE != win_stdout_handle_) {
            if (win_out_mode_saved_) {
                ::SetConsoleMode(static_cast<HANDLE>(win_stdout_handle_), win_original_out_mode_);
            }
            if (win_cursor_saved_) {
                CONSOLE_CURSOR_INFO cci{};
                cci.dwSize   = 25;
                cci.bVisible = win_cursor_visible_ ? TRUE : FALSE;
                ::SetConsoleCursorInfo(static_cast<HANDLE>(win_stdout_handle_), &cci);
            }
        }
        if (win_output_cp_saved_) {
            ::SetConsoleOutputCP(win_original_output_cp_);
        }
        win_stdout_handle_   = NULLPTR;
        win_out_mode_saved_  = false;
        win_cursor_saved_    = false;
        win_output_cp_saved_ = false;
#endif
        return false;
    }

    // Enter alternate screen buffer + permanently hide the real cursor.
    // The synthetic reverse-video cursor block inside the editor line is the
    // only indicator of input position, eliminating all cursor flicker.
    EnterAlternateScreen();
    ppp::HideConsoleCursor(true);

    std::atexit([]() noexcept {
        ConsoleUI& self = ConsoleUI::GetInstance();
        if (self.altscreen_entered_) {
            ppp::HideConsoleCursor(false);
            self.LeaveAlternateScreen();
        }
#if defined(_WIN32)
        // Restore the console output code page on abnormal exit so that
        // the user's shell is not left in UTF-8 mode if the process is
        // killed without going through Stop().
        if (self.win_output_cp_saved_) {
            ::SetConsoleOutputCP(self.win_original_output_cp_);
        }
#endif
    });

    force_redraw_.store(true, std::memory_order_release);
    dirty_.store(true, std::memory_order_release);

    try {
        render_thread_ = std::thread([this]() noexcept { RenderLoop(); });
        input_thread_  = std::thread([this]() noexcept { InputLoop(); });
    } catch (...) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeOptionalUiStartFailed);
        running_.store(false, std::memory_order_release);
        if (render_thread_.joinable()) {
            render_thread_.join();
        }
        if (input_thread_.joinable()) {
            input_thread_.join();
        }
        RestoreInputTerminal();
        ppp::HideConsoleCursor(false);
        LeaveAlternateScreen();
        return false;
    }

    AppendLine("Console UI started. Type 'openppp2 help' for commands.");

    // Redirect telemetry console output into the TUI event buffer instead
    // of stderr.  The file sink is unaffected.
    ppp::telemetry::SetConsoleSink(&TelemetryToConsoleUI);

    return true;
}

void ConsoleUI::Stop() noexcept {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    // Unregister the telemetry console sink so that the backend reverts to
    // stderr output after the TUI tears down.  Must happen before the render
    // thread joins, to avoid a use-after-teardown race.
    ppp::telemetry::SetConsoleSink(nullptr);

    // Wake the render thread so it exits its condition-variable wait immediately
    // rather than blocking up to the full 100 ms timeout.
    render_cv_.notify_all();

    if (render_thread_.joinable()) {
        render_thread_.join();
    }
    if (input_thread_.joinable()) {
        input_thread_.join();
    }


    RestoreInputTerminal();

    // Leave the alternate-screen buffer: this restores whatever the user's
    // console displayed before Start() was called (shell prompt, scrollback,
    // etc.).  The real cursor must be made visible again before we exit.
    LeaveAlternateScreen();
    ppp::HideConsoleCursor(false);

#if defined(_WIN32)
    if (NULLPTR != win_stdout_handle_ && INVALID_HANDLE_VALUE != win_stdout_handle_) {
        if (win_out_mode_saved_) {
            ::SetConsoleMode(static_cast<HANDLE>(win_stdout_handle_), win_original_out_mode_);
        }
        if (win_cursor_saved_) {
            CONSOLE_CURSOR_INFO cci{};
            cci.dwSize   = 25;
            cci.bVisible = win_cursor_visible_ ? TRUE : FALSE;
            ::SetConsoleCursorInfo(static_cast<HANDLE>(win_stdout_handle_), &cci);
        }
    }
    // Restore the original console output code page when Start() saved it.
    if (win_output_cp_saved_) {
        ::SetConsoleOutputCP(win_original_output_cp_);
    }
    win_stdout_handle_  = NULLPTR;
    win_out_mode_saved_ = false;
    win_cursor_saved_   = false;
    win_output_cp_saved_ = false;
#endif
}

// ---------------------------------------------------------------------------
// Alternate-screen helpers
// ---------------------------------------------------------------------------

void ConsoleUI::EnterAlternateScreen() noexcept {
    if (altscreen_entered_) {
        return;
    }

    if (vt_enabled_) {
        std::fwrite(kAltScreenOn, 1u, sizeof(kAltScreenOn) - 1u, stdout);
        std::fwrite(kClearScreen, 1u, sizeof(kClearScreen) - 1u, stdout);
        std::fflush(stdout);
    }

    altscreen_entered_ = true;
}

void ConsoleUI::LeaveAlternateScreen() noexcept {
    if (!altscreen_entered_) {
        return;
    }

    if (vt_enabled_) {
        // Move cursor to a sane location, clear residual attributes, then
        // swap the buffer back so the user sees their original shell state.
        std::fwrite(kColorReset, 1u, sizeof(kColorReset) - 1u, stdout);
        std::fwrite(kAltScreenOff, 1u, sizeof(kAltScreenOff) - 1u, stdout);
        std::fflush(stdout);
    }

    altscreen_entered_ = false;
}

// ---------------------------------------------------------------------------
// Dirty-marker (inlined by mutators)
// ---------------------------------------------------------------------------

void ConsoleUI::MarkDirty() noexcept {
    dirty_.store(true, std::memory_order_release);
    // Wake the render thread immediately so it does not wait the full CV timeout.
    render_cv_.notify_one();
}

// ---------------------------------------------------------------------------
// Public data-update methods
// ---------------------------------------------------------------------------

void ConsoleUI::UpdateStatus(const ppp::string& status_text) noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        status_queue_.push(status_text);
    }
    MarkDirty();
}

void ConsoleUI::AppendLine(const ppp::string& line) noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        cmd_lines_.push_back(line);
        while (kMaxCmdLines < static_cast<int>(cmd_lines_.size())) {
            cmd_lines_.pop_front();
        }
    }
    MarkDirty();
}

void ConsoleUI::SetInfoLines(const ppp::vector<ppp::string>& lines) noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        // Preserve the current scroll position so that periodic tick updates
        // (which call SetInfoLines every ~1 s) do not discard the user's scroll
        // position achieved via Home / End.  The scroll offset is clamped against
        // the new content size inside RenderFrame().
        bool was_empty = info_lines_.empty();
        info_lines_    = lines;

        // Only jump to the top when content is being populated for the first time;
        // subsequent updates keep whatever scroll position the user has set.
        if (was_empty) {
            info_scroll_ = 0;
        }
    }
    MarkDirty();
}

void ConsoleUI::SetTelemetryLines(const ppp::vector<ppp::string>& lines) noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        telemetry_lines_ = lines;
    }
    MarkDirty();
}

bool ConsoleUI::IsRunning() noexcept {
    return GetInstance().running_.load(std::memory_order_acquire);
}

void ConsoleUI::AppendTelemetryEventLine(const char* line) noexcept {
    if (!line || '\0' == line[0]) {
        return;
    }

    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    ppp::string clean = StripAnsiEscapes(ppp::string(line));

    // Strip trailing newline / carriage-return
    while (!clean.empty() && ('\n' == clean.back() || '\r' == clean.back())) {
        clean.pop_back();
    }
    if (clean.empty()) {
        return;
    }

    {
        std::lock_guard<std::mutex> scope(lock_);
        telemetry_event_lines_.push_back(std::move(clean));
        while (kMaxTelemetryEventLines < static_cast<int>(telemetry_event_lines_.size())) {
            telemetry_event_lines_.pop_front();
        }
    }
    // Telemetry can be high-volume.  Always set dirty_ so the render loop will
    // repaint on its regular 100 ms cadence, but throttle CV notifications to
    // avoid one wakeup/futex per event during bursts.
    dirty_.store(true, std::memory_order_release);
    uint64_t now_ms = ppp::GetTickCount();
    uint64_t last_ms = last_telemetry_dirty_notify_ms_.load(std::memory_order_acquire);
    if (now_ms < last_ms || now_ms - last_ms >= kTelemetryDirtyNotifyIntervalMs) {
        if (last_telemetry_dirty_notify_ms_.compare_exchange_strong(
                last_ms,
                now_ms,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            render_cv_.notify_one();
        }
    }
}

void ConsoleUI::SetRuntimeSnapshot(const runtime::RuntimeSnapshot& snapshot) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    runtime_snapshot_ = snapshot;
    if (p2p_priority_handler_ && !snapshot.p2p_priority.empty()) {
        p2p_priority_ = snapshot.p2p_priority;
    }
    runtime_snapshot_.p2p_priority = p2p_priority_;
}

void ConsoleUI::SetP2PPriorityHandler(P2PPriorityHandler handler) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    p2p_priority_handler_ = std::move(handler);
}

void ConsoleUI::SetP2PPeerPriorityHandler(P2PPeerPriorityHandler handler) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    p2p_peer_priority_handler_ = std::move(handler);
}

bool ConsoleUI::SetP2PPriority(const ppp::string& priority) noexcept {
    if (priority != "ipv4-first" && priority != "ipv6-first" && priority != "relay-first") return false;
    P2PPriorityHandler handler;
    {
        std::lock_guard<std::mutex> scope(lock_);
        handler = p2p_priority_handler_;
    }
    if (handler && !handler(priority)) return false;
    {
        std::lock_guard<std::mutex> scope(lock_);
        p2p_priority_ = priority;
        runtime_snapshot_.p2p_priority = priority;
    }
    MarkDirty();
    return true;
}

bool ConsoleUI::SetP2PPeerPriority(const ppp::string& peer_uuid, const ppp::string& priority) noexcept {
    if (priority != "ipv4-first" && priority != "ipv6-first" && priority != "relay-first") return false;
    ppp::string normalized;
    normalized.reserve(peer_uuid.size());
    for (char ch : peer_uuid) {
        if (ch == '-') continue;
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
        normalized.push_back(static_cast<char>(ch >= 'A' && ch <= 'F' ? ch + ('a' - 'A') : ch));
    }
    if (normalized.size() != 32u) return false;
    P2PPeerPriorityHandler handler;
    {
        std::lock_guard<std::mutex> scope(lock_);
        handler = p2p_peer_priority_handler_;
    }
    if (handler && !handler(normalized, priority)) return false;
    MarkDirty();
    return true;
}

ppp::string ConsoleUI::GetP2PPriority() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    return p2p_priority_;
}

void ConsoleUI::ClearTelemetryEventLines() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        telemetry_event_lines_.clear();
    }
    MarkDirty();
}

// ---------------------------------------------------------------------------
// Internal: drain status queue
// ---------------------------------------------------------------------------

void ConsoleUI::DrainStatusQueue() noexcept {
    // Short-lock: swap the entire queue out to a local copy so that
    // UpdateStatus() callers are not blocked while we do string processing.
    std::queue<ppp::string> local_queue;
    {
        std::lock_guard<std::mutex> scope(lock_);
        local_queue.swap(status_queue_);
    }

    if (local_queue.empty()) {
        return;
    }

    // Process all pending entries outside the lock (ToLower, find, substr).
    // Only the last entry's values are written back; earlier ones are
    // effectively coalesced, which matches the original sequential semantics.
    ppp::string last_state;
    ppp::string last_speed;

    while (false == local_queue.empty())
    {
        ppp::string txt = local_queue.front();
        local_queue.pop();

        ppp::string lower = ppp::ToLower(txt);

        if (ppp::string::npos != lower.find("disconnect"))
        {
            last_state = "Disconnected";
        }
        elif (ppp::string::npos != lower.find("reconnect"))
        {
            last_state = "Reconnecting";
        }
        elif (ppp::string::npos != lower.find("established") ||
             ppp::string::npos != lower.find("connected"))
        {
            last_state = "Established";
        }
        elif (ppp::string::npos != lower.find("connect"))
        {
            last_state = "Connecting";
        }
        else
        {
            last_state = txt;
        }

        last_speed.clear();

        std::size_t rx_pos = lower.find("rx=");
        std::size_t tx_pos = lower.find("tx=");

        if (ppp::string::npos != rx_pos)
        {
            std::size_t end_pos = lower.find(' ', rx_pos);
            ppp::string rx_val = (ppp::string::npos == end_pos)
                ? txt.substr(rx_pos + 3u)
                : txt.substr(rx_pos + 3u, end_pos - rx_pos - 3u);
            last_speed += UseUnicodeUiGlyphs() ? "\xe2\x86\x93 " : "rx ";
            last_speed += rx_val;
        }

        if (ppp::string::npos != tx_pos)
        {
            std::size_t end_pos = lower.find(' ', tx_pos);
            ppp::string tx_val = (ppp::string::npos == end_pos)
                ? txt.substr(tx_pos + 3u)
                : txt.substr(tx_pos + 3u, end_pos - tx_pos - 3u);

            if (false == last_speed.empty())
            {
                last_speed += "  ";
            }

            last_speed += UseUnicodeUiGlyphs() ? "\xe2\x86\x91 " : "tx ";
            last_speed += tx_val;
        }
    }

    // Short-lock: write the final computed state back.
    {
        std::lock_guard<std::mutex> scope(lock_);
        vpn_state_text_ = std::move(last_state);
        speed_text_      = std::move(last_speed);
    }
}

// ---------------------------------------------------------------------------
// Render loop
// ---------------------------------------------------------------------------

void ConsoleUI::RenderLoop() noexcept {
    while (running_.load(std::memory_order_acquire)) {
        DrainStatusQueue();

        // Status updates that change vpn_state / speed text should trigger a
        // repaint too; DrainStatusQueue marks dirty implicitly via the public
        // UpdateStatus entry point.  The render thread coalesces multiple
        // dirty marks into a single frame draw.
        bool need_redraw = dirty_.exchange(false, std::memory_order_acq_rel)
                        || force_redraw_.load(std::memory_order_acquire);

        // Detect window resize even when the data model has not changed —
        // a resize requires a full forced clear to avoid stale artefacts.
        int probe_w = 0;
        int probe_h = 0;
        if (ppp::GetConsoleWindowSize(probe_w, probe_h)) {
            if (probe_w != last_width_ || probe_h != last_height_) {
                force_redraw_.store(true, std::memory_order_release);
                need_redraw = true;
            }
        }

        if (need_redraw) {
            RenderFrame();
        }

        // Wait for up to 100 ms or until MarkDirty()/Stop() fires the CV.
        // The 100 ms cap ensures window-resize detection still fires promptly
        // even when no data-model change has occurred.
        {
            std::unique_lock<std::mutex> lk(render_cv_mutex_);
            render_cv_.wait_for(lk, std::chrono::milliseconds(100),
                [this]() noexcept -> bool {
                    return !running_.load(std::memory_order_acquire)
                        || dirty_.load(std::memory_order_acquire)
                        || force_redraw_.load(std::memory_order_acquire);
                });
        }
    }

    // Final frame on exit ensures the terminal state is deterministic before
    // Stop() swaps out of the alternate screen buffer.
    force_redraw_.store(true, std::memory_order_release);
    RenderFrame();
}

// ---------------------------------------------------------------------------
// Core frame renderer
// ---------------------------------------------------------------------------

void ConsoleUI::RenderFrame() noexcept {
    // -----------------------------------------------------------------------
    // 1.  Snapshot terminal dimensions
    // -----------------------------------------------------------------------
    int width  = 120;
    int height = 46;
    if (!ppp::GetConsoleWindowSize(width, height)) {
        width  = 120;
        height = 46;
    }
    if (40 > width) {
        width = 40;
    }
    if (20 > height) {
        height = 20;
    }

    // -----------------------------------------------------------------------
    // 2.  Compute layout
    //
    //  Fixed header rows (top to bottom):
    //    0:  top border
    //    1:  hint row 1 (PageUp/Down + title)
    //    2:  hint row 2 (Home/End)
    //    3-7: ASCII art (5 rows)
    //    8:  empty row
    //    9:  header separator
    //  => kHeaderRows = 10
    //
    //  Fixed footer rows (bottom to top):
    //    -1: bottom border
    //    -2: status bar
    //    -3: status separator
    //    -4: input row
    //    -5: input separator
    //  => kFooterRows = 5
    //
    //  Middle = height - kHeaderRows - kFooterRows
    //  Split:  info_h + 1 (separator) + cmd_h = middle
    // -----------------------------------------------------------------------
    static constexpr int kFooterRows = 5;
    const int kHeaderRows = (height >= 35) ? 10 : 4;

    int middle = height - kHeaderRows - kFooterRows;
    if (0 > middle) {
        middle = 0;
    }

    // -----------------------------------------------------------------------
    // 2b. Snapshot guarded state BEFORE computing layout so we can
    //     dynamically balance info/cmd based on actual content sizes.
    // -----------------------------------------------------------------------
    ppp::vector<ppp::string> info_snap;
    ppp::vector<ppp::string> telemetry_snap;
    std::deque<ppp::string>  tele_event_snap;
    int                      info_scroll;
    std::deque<ppp::string>  cmd_snap;
    int                      cmd_scroll;
    ppp::string              input_snap;
    std::size_t              cursor_snap;

    {
        std::lock_guard<std::mutex> scope(lock_);
        info_snap       = info_lines_;
        telemetry_snap  = telemetry_lines_;
        tele_event_snap = telemetry_event_lines_;
        info_scroll     = info_scroll_;
        cmd_snap        = cmd_lines_;
        cmd_scroll      = cmd_scroll_;
        input_snap      = input_buffer_;
        cursor_snap     = input_cursor_;
    }

    // -----------------------------------------------------------------------
    // 2c. Dynamic split: allocate middle rows between info and cmd based
    //     on their actual content sizes, avoiding one panel starving the other.
    // -----------------------------------------------------------------------
    int info_total      = static_cast<int>(info_snap.size());
    int tele_total      = static_cast<int>(telemetry_snap.size());
    int tele_event_total = static_cast<int>(tele_event_snap.size());
    int cmd_total       = static_cast<int>(cmd_snap.size());

    int info_h, cmd_h;

    if (3 > middle) {
        info_h = middle > 0 ? 1 : 0;
        cmd_h  = middle > 1 ? 1 : 0;
    } else if (0 == info_total && 0 == cmd_total) {
        // Both empty: default 60/40 split.
        info_h = std::max(2, (middle - 1) * 3 / 5);
        cmd_h  = std::max(1, middle - 1 - info_h);
    } else if (0 == cmd_total) {
        // No command output — give info all remaining space (minus the
        // separator), capped so cmd keeps at least 1 row placeholder.
        info_h = std::max(2, middle - 2);   // 1 for separator, 1 for cmd placeholder
        cmd_h  = middle - 1 - info_h;       // <= 1
        if (0 > cmd_h) { cmd_h = 0; }
        if (cmd_h > 1) { cmd_h = 1; }
    } else if (0 == info_total) {
        // No info lines — give cmd most of the space.
        info_h = 1;
        cmd_h  = middle - 1 - info_h;
        if (1 > cmd_h) { cmd_h = 1; }
    } else {
        // Both have content.  Use a content-proportional split but
        // guarantee each side gets at least 1 visible line and at most
        // 80% of the available middle area.
        int avail = middle - 1;  // one row for the separator

        // Compute ideal heights proportional to content depth.
        int sum = info_total + cmd_total;
        int info_prop = (info_total * avail) / sum;
        int cmd_prop  = avail - info_prop;

        // Enforce minimums.
        if (1 > info_prop)  { info_prop = 1; }
        if (1 > cmd_prop)   { cmd_prop  = 1; }

        // Enforce maximums (80% cap) so one panel can never totally
        // eclipse the other.
        int max_each = (avail * 4) / 5;   // 80% of available
        if (info_prop > max_each) {
            info_prop = max_each;
            cmd_prop  = avail - info_prop;
            if (1 > cmd_prop) { cmd_prop = 1; }
        }
        if (cmd_prop > max_each) {
            cmd_prop  = max_each;
            info_prop = avail - cmd_prop;
            if (1 > info_prop) { info_prop = 1; }
        }

        // Ensure both fit exactly in avail.
        if (info_prop + cmd_prop > avail) {
            // Reduce the larger one.
            if (info_prop > cmd_prop) {
                info_prop = avail - cmd_prop;
            } else {
                cmd_prop = avail - info_prop;
            }
        }
        if (info_prop + cmd_prop < avail) {
            cmd_prop = avail - info_prop;
        }

        info_h = info_prop;
        cmd_h  = cmd_prop;
    }

    // -----------------------------------------------------------------------
    // 3.  Clamp scroll offsets using the dynamically computed panel heights.
    //     In two-column mode the info panel can display 2*info_h lines.
    // -----------------------------------------------------------------------
    {
        int total       = static_cast<int>(info_snap.size());
        static constexpr int kTwoColMinInner = 76;
        const bool two_col = ((width - 2) >= kTwoColMinInner)
                          && (tele_total > 0 || tele_event_total > 0);
        // In two-column mode only the left column scrolls; right column is static.
        // In single-column mode info + telemetry status + events are combined.
        int combined    = two_col ? total : (total + tele_total + tele_event_total);
        int max_scroll  = std::max(0, combined - info_h);
        if (info_scroll > max_scroll) {
            info_scroll = max_scroll;
            std::lock_guard<std::mutex> s(lock_);
            info_scroll_ = info_scroll;
        }
    }

    {
        int total       = static_cast<int>(cmd_snap.size());
        int max_scroll  = std::max(0, total - cmd_h);
        if (cmd_scroll > max_scroll) {
            cmd_scroll = max_scroll;
            std::lock_guard<std::mutex> s(lock_);
            cmd_scroll_ = cmd_scroll;
        }
    }

    // -----------------------------------------------------------------------
    // 4.  Build frame string
    //
    // The cursor is permanently hidden by Start(); the editor line embeds a
    // reverse-video block at the caret position, so no per-frame cursor
    // show/hide escapes are emitted here.  A full-screen clear (\x1b[2J) is
    // only issued on the very first frame or after a window-size change —
    // subsequent frames rely on \x1b[H (cursor-home) plus full-width line
    // overwrites, eliminating the flicker that would otherwise be produced
    // by clearing the screen on every tick.
    // -----------------------------------------------------------------------
    ppp::string frame;
    frame.reserve(static_cast<std::size_t>(width * height) * 8u);

    bool forced = force_redraw_.exchange(false, std::memory_order_acq_rel);
    last_width_  = width;
    last_height_ = height;

    if (vt_enabled_) {
        if (forced) {
            frame += kClearScreen;
        } else {
            frame += kCursorHome;
        }
    }

    int inner = width - 2;  // display columns inside borders

    // --- Row 0: top border ┌─────┐ ---
    {
        frame += BoxBL();
        frame += RepeatHoriz(width - 2);
        frame += BoxBR();
        frame += "\n";
    }

    // --- Row 1: hint 1 + right-aligned title ---
    {
        static constexpr const char kLeftHint1[]   = " PageUp/PageDown: Scroll command input/output";
        const bool unicode_ui = UseUnicodeUiGlyphs();
        const char* kRightTitle = unicode_ui
            ? "PPP PRIVATE NETWORK\xe2\x84\xa2 2 "
            : "PPP PRIVATE NETWORK(TM) 2 ";
        const int kRightTitleDisplayW = unicode_ui ? 23 : 26;

        int left_avail  = inner - kRightTitleDisplayW;
        if (0 > left_avail) {
            left_avail = 0;
        }

        frame += BoxVV();
        frame += FitWidth(kLeftHint1, left_avail);
        frame += kRightTitle;
        frame += BoxVV();
        frame += "\n";
    }

    // --- Row 2: hint 2 ---
    {
        static constexpr const char kLeftHint2[] = " Home/End       : Scroll openppp2 info";
        frame += BoxContentRow(kLeftHint2, width);
    }

    // --- Rows 3-7: ASCII art (5 lines) ---
    // Skip art when terminal is short to free space for info content.
    const bool show_art = (height >= 35);
    if (show_art) {
        for (int i = 0; i < 5; ++i) {
            frame += RenderArtLine(ppp::string(kArtLines[i]), inner, vt_enabled_);
        }

        // --- Row 8: empty row ---
        frame += BoxContentRow("", width);
    }

    // --- Row 9: header separator ---
    frame += BoxSepRow(width);

    // --- Info section (info_h rows) ---
    // Two-column mode when inner width >= 76 display columns and there is
    // any telemetry content (status snapshot or event stream).
    // Left column shows environment info, right column shows telemetry
    // status lines at the top with recent event lines filling the rest.
    {
        int total  = static_cast<int>(info_snap.size());
        int start  = info_scroll;  // 0 = top of info content

        // Minimum inner width needed for two-column mode:
        // Each column needs at least 40 chars of content + 1 separator + 2 borders.
        static constexpr int kTwoColMinInner = 76;
        const bool two_col = (inner >= kTwoColMinInner)
                          && (tele_total > 0 || tele_event_total > 0);

        if (two_col) {
            // Left column: environment info from info_snap.
            // Right column: telemetry status snapshot (top) + recent events (bottom).
            int split_col = inner / 2 + 1;  // display column for center │

            // In the right column, status lines come first, then event lines.
            // If there are more combined lines than info_h, the most recent
            // event lines are shown (older ones are truncated from the bottom).
            int right_total = tele_total + tele_event_total;
            int right_event_start = 0;  // offset within tele_event_snap to start from
            if (right_total > info_h) {
                // More content than rows — trim events from the front.
                int overflow = right_total - info_h;
                right_event_start = std::min(overflow, tele_event_total);
            }

            for (int i = 0; i < info_h; ++i) {
                int left_idx = start + i;

                ppp::string left_text;
                if (0 <= left_idx && left_idx < total) {
                    left_text = " " + info_snap[static_cast<std::size_t>(left_idx)];
                }

                // Build right column line: status first, then events.
                ppp::string right_text;
                if (i < tele_total) {
                    right_text = " " + telemetry_snap[static_cast<std::size_t>(i)];
                } else {
                    int event_idx = right_event_start + (i - tele_total);
                    if (event_idx >= 0 && event_idx < tele_event_total) {
                        right_text = " " + tele_event_snap[static_cast<std::size_t>(event_idx)];
                    }
                }

                frame += BoxSplitRow(left_text, right_text, width, split_col);
            }
        } else {
            // Single column: info lines, then telemetry status, then event lines.
            for (int i = 0; i < info_h; ++i) {
                int idx = start + i;
                if (0 <= idx && idx < total) {
                    frame += BoxContentRow(" " + info_snap[static_cast<std::size_t>(idx)], width);
                } else {
                    int tele_idx = idx - total;
                    if (tele_idx >= 0 && tele_idx < tele_total) {
                        frame += BoxContentRow(" " + telemetry_snap[static_cast<std::size_t>(tele_idx)], width);
                    } else {
                        int event_idx = tele_idx - tele_total;
                        if (event_idx >= 0 && event_idx < tele_event_total) {
                            frame += BoxContentRow(" " + tele_event_snap[static_cast<std::size_t>(event_idx)], width);
                        } else {
                            frame += BoxContentRow("", width);
                        }
                    }
                }
            }
        }
    }

    // --- Separator between info and cmd ---
    frame += BoxSepRow(width);

    // --- Cmd section (cmd_h rows) ---
    {
        int total = static_cast<int>(cmd_snap.size());
        // cmd_scroll = 0 → show newest (bottom); > 0 → scrolled up
        int start = total - cmd_h - cmd_scroll;
        if (0 > start) {
            start = 0;
        }

        for (int i = 0; i < cmd_h; ++i) {
            int idx = start + i;
            if (0 <= idx && idx < total) {
                frame += BoxContentRow(" " + cmd_snap[static_cast<std::size_t>(idx)], width);
            } else {
                frame += BoxContentRow("", width);
            }
        }
    }

    // --- Input separator ---
    frame += BoxSepRow(width);

    // --- Input row ---
    int cursor_col = 0;
    {
        frame += BoxVV();

        if (input_snap.empty()) {
            // Placeholder mode: show the white-block cursor at column 2 (after "> ")
            // followed by the dim placeholder tip text.
            static constexpr const char kPrompt[]       = "> ";
            static constexpr const char kPlaceholder[]  = "Exec openppp command or system commands.";
            static constexpr int        kPromptLen      = 2;            // "> "
            static constexpr int        kCursorLen      = 1;            // white block
            int                         remaining      = inner - kPromptLen - kCursorLen;

            if (vt_enabled_) {
                frame += kPrompt;
                frame += kColorWhiteBg;
                frame += " ";
                frame += kColorReset;
                frame += kColorDim;
                if (0 < remaining) {
                    frame += FitWidth(kPlaceholder, remaining);
                }
                frame += kColorReset;
            } else {
                frame += kPrompt;
                frame += " ";
                if (0 < remaining) {
                    frame += FitWidth(kPlaceholder, remaining);
                }
            }
            cursor_col = 2;
        } else {
            ppp::string editor_content =
                BuildEditorLine("> ", input_snap, cursor_snap, inner, vt_enabled_, cursor_col);
            frame += editor_content;
        }

        frame += BoxVV();
        frame += "\n";
    }

    // --- Status separator ---
    frame += BoxSplitSepRow(width, width * 3 / 5);

    // --- Status bar: split row ---
    // Left panel  = error severity info (existing logic)
    // Right panel = VPN state + speed text from DrainStatusQueue()
    {
        auto select_status_color = [](ppp::diagnostics::ErrorSeverity severity) noexcept -> const char* {
            switch (severity) {
            case ppp::diagnostics::ErrorSeverity::kTrace:
                return kColorTrace;
            case ppp::diagnostics::ErrorSeverity::kDebug:
                return kColorDebug;
            case ppp::diagnostics::ErrorSeverity::kInfo:
                return kColorInfo;
            case ppp::diagnostics::ErrorSeverity::kWarn:
                return kColorWarn;
            case ppp::diagnostics::ErrorSeverity::kError:
                return kColorError;
            case ppp::diagnostics::ErrorSeverity::kFatal:
                return kColorFatal;
            default:
                return NULLPTR;
            }
        };

        // Snapshot vpn_state_text_ and speed_text_ under the same lock
        // that DrainStatusQueue() writes them.
        ppp::string vpn_snap;
        ppp::string speed_snap;
        {
            std::lock_guard<std::mutex> scope(lock_);
            vpn_snap   = vpn_state_text_;
            speed_snap = speed_text_;
        }

        // Build left panel: error severity text
        ppp::string status_text;
        const char* status_color = NULLPTR;
        {
            ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCodeSnapshot();
            ppp::diagnostics::ErrorSeverity severity = ppp::diagnostics::GetErrorSeverity(code);
            
            const char* severity_name = ppp::diagnostics::GetErrorSeverityName(severity);
            uint64_t err_ts     = ppp::diagnostics::GetLastErrorTimestamp();
            uint64_t now_ms     = ppp::threading::Executors::GetTickCount();

            status_color  = select_status_color(severity);
            status_text   = "[";
            status_text  += (NULLPTR == severity_name) ? "UNKNOWN" : severity_name;
            status_text  += "] ";
            status_text  += ppp::diagnostics::FormatErrorTriplet(code);

            if (ppp::diagnostics::ErrorCode::Success != code && 0u < err_ts) {
                status_text += " (" + FormatAge(now_ms, err_ts) + ")";
            }

            status_text += "  | T:";
            status_text += ppp::telemetry::IsConsoleLogEnabled() ? "L" : "-";
            status_text += ppp::telemetry::IsConsoleMetricEnabled() ? "M" : "-";
            status_text += ppp::telemetry::IsConsoleSpanEnabled() ? "S" : "-";
            status_text += " @";
            status_text += std::to_string(ppp::telemetry::GetMinLevel());
            status_text += " (openppp2 telemetry help)";
        }

        // Build right panel: "VPN: state  ↑ tx  ↓ rx"
        ppp::string right_text = "VPN: ";
        if (!vpn_snap.empty()) {
            right_text += vpn_snap;
        } else {
            right_text += "n/a";
        }
        if (!speed_snap.empty()) {
            right_text += "  ";
            right_text += speed_snap;
        }

        // Use BoxSplitRow with ~60/40 split
        int split_col = width * 3 / 5;

        if (vt_enabled_ && NULLPTR != status_color && '\0' != status_color[0]) {
            // Colorize the left panel content inside the split row.
            // BoxSplitRow is static and doesn't know about colors, so we
            // build the row manually with color codes on the left panel.
            int left_inner  = split_col - 1;
            int right_inner = width - split_col - 2;

            ppp::string row;
            row.reserve(static_cast<std::size_t>(width) * 4u + 64u);
            row += BoxVV();
            row += status_color;
            row += FitWidth(status_text, left_inner);
            row += kColorReset;
            row += BoxVV();
            row += FitWidth(right_text, right_inner);
            row += BoxVV();
            row += "\n";
            frame += row;
        } else {
            frame += BoxSplitRow(status_text, right_text, width, split_col);
        }
    }

    // --- Bottom border (split to match status bar divider) ---
    frame += BoxBotSplitRow(width, width * 3 / 5);

    // The real cursor stays hidden; no trailing cursor-position or
    // show-cursor escape is needed — the synthetic reverse-video block
    // inside the editor line conveys the caret location to the user.
    (void)cursor_col;

    // -----------------------------------------------------------------------
    // 6.  Write frame to stdout in one atomic write
    //
    // Important: do NOT end the last row with '\n'.  The frame already fills
    // the whole terminal height; emitting one extra newline after the bottom
    // border would scroll the terminal by one row and visually drop the top
    // border (the "roof").
    // -----------------------------------------------------------------------
    if (!frame.empty() && '\n' == frame.back()) {
        frame.pop_back();
    }

    std::fwrite(frame.data(), 1u, frame.size(), stdout);
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Input editing handlers
// ---------------------------------------------------------------------------

void ConsoleUI::HandleEnter() noexcept {
    ppp::string command_line;
    {
        std::lock_guard<std::mutex> scope(lock_);
        command_line = input_buffer_;
        input_buffer_.clear();
        input_cursor_          = 0u;
        history_index_         = -1;
        history_edit_backup_.clear();

        if (!command_line.empty()) {
            if (history_.empty() || history_.back() != command_line) {
                history_.push_back(command_line);
                while (kMaxHistoryEntries < static_cast<int>(history_.size())) {
                    history_.pop_front();
                }
            }
        }
    }

    MarkDirty();
    ExecuteCommand(command_line);
}

void ConsoleUI::HandleHistoryUp() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (history_.empty()) {
            return;
        }

        if (-1 == history_index_) {
            history_edit_backup_ = input_buffer_;
            history_index_       = static_cast<int>(history_.size()) - 1;
        } else if (0 < history_index_) {
            --history_index_;
        }

        if (0 <= history_index_ && static_cast<int>(history_.size()) > history_index_) {
            input_buffer_ = history_[static_cast<std::size_t>(history_index_)];
            input_cursor_ = input_buffer_.size();
        }
    }
    MarkDirty();
}

void ConsoleUI::HandleHistoryDown() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (history_.empty() || -1 == history_index_) {
            return;
        }

        int last_index = static_cast<int>(history_.size()) - 1;
        if (history_index_ < last_index) {
            ++history_index_;
            input_buffer_ = history_[static_cast<std::size_t>(history_index_)];
        } else {
            history_index_ = -1;
            input_buffer_  = history_edit_backup_;
            history_edit_backup_.clear();
        }

        input_cursor_ = input_buffer_.size();
    }
    MarkDirty();
}

void ConsoleUI::InsertInputChar(char ch) noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (input_cursor_ > input_buffer_.size()) {
            input_cursor_ = input_buffer_.size();
        }
        input_buffer_.insert(input_cursor_, 1u, ch);
        ++input_cursor_;
    }
    MarkDirty();
}

void ConsoleUI::MoveCursorLeft() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (0u < input_cursor_) {
            --input_cursor_;
        }
    }
    MarkDirty();
}

void ConsoleUI::MoveCursorRight() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (input_buffer_.size() > input_cursor_) {
            ++input_cursor_;
        }
    }
    MarkDirty();
}

void ConsoleUI::MoveCursorLineStart() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        input_cursor_ = 0u;
    }
    MarkDirty();
}

void ConsoleUI::MoveCursorLineEnd() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        input_cursor_ = input_buffer_.size();
    }
    MarkDirty();
}

void ConsoleUI::EraseBeforeCursor() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (0u < input_cursor_ && !input_buffer_.empty()) {
            input_buffer_.erase(input_cursor_ - 1u, 1u);
            --input_cursor_;
        }
    }
    MarkDirty();
}

void ConsoleUI::EraseAtCursor() noexcept {
    {
        std::lock_guard<std::mutex> scope(lock_);
        if (input_buffer_.size() > input_cursor_) {
            input_buffer_.erase(input_cursor_, 1u);
        }
    }
    MarkDirty();
}

// ---------------------------------------------------------------------------
// Scroll handlers
// ---------------------------------------------------------------------------

void ConsoleUI::ScrollInfoBy(int delta) noexcept {
    int w = 120;
    int h = 46;
    ppp::GetConsoleWindowSize(w, h);

    static constexpr int kFtrRows = 5;
    const int kHdrRows = (h >= 35) ? 10 : 4;
    int middle = std::max(0, h - kHdrRows - kFtrRows);
    int info_h  = (3 <= middle) ? std::max(2, (middle - 1) * 3 / 5)
                                : (middle > 0 ? 1 : 0);
    if (1 > info_h) {
        info_h = 1;
    }

    int inner = w - 2;
    {
        std::lock_guard<std::mutex> scope(lock_);
        int total  = static_cast<int>(info_lines_.size());
        int tele   = static_cast<int>(telemetry_lines_.size());
        int events = static_cast<int>(telemetry_event_lines_.size());
        static constexpr int kTwoColMinInner = 76;
        const bool two_col = (inner >= kTwoColMinInner) && (tele > 0 || events > 0);
        int combined = two_col ? total : (total + tele + events);

        int next = info_scroll_ + delta;
        if (0 > next) {
            next = 0;
        }

        int max_scroll = std::max(0, combined - info_h);
        if (next > max_scroll) {
            next = max_scroll;
        }

        info_scroll_ = next;
    }
    MarkDirty();
}

void ConsoleUI::ScrollInfoPage(int direction) noexcept {
    int w = 120;
    int h = 46;
    ppp::GetConsoleWindowSize(w, h);

    static constexpr int kFooterRows = 5;
    const int kHeaderRows = (h >= 35) ? 10 : 4;
    int middle = h - kHeaderRows - kFooterRows;
    if (3 > middle) {
        middle = 3;
    }
    int info_h = std::max(2, (middle - 1) * 3 / 5);
    int page   = std::max(1, info_h - 1);
    ScrollInfoBy(direction * page);
}

void ConsoleUI::ScrollCmdBy(int delta) noexcept {
    // Compute the visible cmd panel height so max_scroll clamps to the last
    // page boundary rather than the last individual line.
    int w = 120;
    int h = 46;
    ppp::GetConsoleWindowSize(w, h);

    static constexpr int kHdrRows = 10;
    static constexpr int kFtrRows = 5;
    int middle = std::max(0, h - kHdrRows - kFtrRows);
    int info_h  = (3 <= middle) ? std::max(2, (middle - 1) * 3 / 5)
                                : (middle > 0 ? 1 : 0);
    int cmd_h   = (3 <= middle) ? std::max(1, middle - 1 - info_h)
                                : (middle > 1 ? 1 : 0);
    if (1 > cmd_h) {
        cmd_h = 1;
    }

    {
        std::lock_guard<std::mutex> scope(lock_);
        int next = cmd_scroll_ + delta;
        if (0 > next) {
            next = 0;
        }

        int max_scroll = std::max(0, static_cast<int>(cmd_lines_.size()) - cmd_h);
        if (next > max_scroll) {
            next = max_scroll;
        }

        cmd_scroll_ = next;
    }
    MarkDirty();
}

void ConsoleUI::ScrollCmdPage(int direction) noexcept {
    int w = 120;
    int h = 46;
    ppp::GetConsoleWindowSize(w, h);

    static constexpr int kHeaderRows = 10;
    static constexpr int kFooterRows = 5;
    int middle = h - kHeaderRows - kFooterRows;
    if (3 > middle) {
        middle = 3;
    }
    int info_h = std::max(2, (middle - 1) * 3 / 5);
    int cmd_h  = std::max(1, middle - 1 - info_h);
    int page   = std::max(1, cmd_h - 1);
    ScrollCmdBy(direction * page);
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

void ConsoleUI::ExecuteCommand(const ppp::string& command_line) noexcept {
    ppp::string cmd = ppp::LTrim(ppp::RTrim(command_line));
    if (cmd.empty()) {
        return;
    }

    AppendLine("> " + cmd);

    ppp::string lower = ppp::ToLower(cmd);

    // -----------------------------------------------------------------------
    // Resolve "openppp2 <sub>" namespace
    // -----------------------------------------------------------------------
    ppp::string openppp2_sub;
    static constexpr const char kNS[] = "openppp2";
    static constexpr std::size_t kNSLen = sizeof(kNS) - 1u;

    if (0u == lower.find(kNS)) {
        if (lower.size() == kNSLen) {
            openppp2_sub = "help";
        } else if (lower.size() > kNSLen && ' ' == lower[kNSLen]) {
            openppp2_sub = ppp::LTrim(lower.substr(kNSLen + 1u));
        }
    }

    if (!openppp2_sub.empty()) {
        if ("help" == openppp2_sub) {
            AppendLine("Available openppp2 commands:");
            AppendLine("  openppp2 help             - Show this help information");
            AppendLine("  openppp2 restart          - Restart the application");
            AppendLine("  openppp2 reload           - Reload configuration (restart)");
            AppendLine("  openppp2 exit             - Exit the application");
            AppendLine("  openppp2 info             - Print full runtime environment snapshot");
            AppendLine("  openppp2 peer status      - Print detailed peer status");
            AppendLine("  openppp2 peer set <uuid> ipv4-first|ipv6-first|relay-first - Set peer P2P priority");
            AppendLine("  openppp2 clear            - Clear command output section");
            AppendLine("  openppp2 telemetry ...    - Telemetry filter controls (status/help/log/metric/span/level/all/quiet/clear)");
            AppendLine("");
            AppendLine("All typed characters are normal input; no single-key hotkeys.");
            return;
        }

        if ("restart" == openppp2_sub || "reload" == openppp2_sub) {
            AppendLine("Requesting application restart...");
            PppApplication::ShutdownApplication(true);
            return;
        }

        if ("exit" == openppp2_sub) {
            AppendLine("Requesting application exit...");
            PppApplication::ShutdownApplication(false);
            return;
        }

        if ("clear" == openppp2_sub) {
            {
                std::lock_guard<std::mutex> scope(lock_);
                cmd_lines_.clear();
                cmd_scroll_ = 0;
            }
            MarkDirty();
            return;
        }

        if ("info" == openppp2_sub) {
            ppp::vector<ppp::string> info_copy;

            // Use the latest periodic snapshot generated by OnTick().  This keeps
            // command execution on the input thread read-only with respect to the
            // application runtime graph.
            {
                std::lock_guard<std::mutex> scope(lock_);
                info_copy = info_lines_;
            }

            if (info_copy.empty()) {
                AppendLine("[No environment info available yet]");
            } else {
                for (const ppp::string& line : info_copy) {
                    AppendLine(line);
                }
            }
            return;
        }

        if ("peer" == openppp2_sub || 0u == openppp2_sub.find("peer ")) {
            const ppp::string peer_command = openppp2_sub == "peer"
                ? ppp::string("status") : ppp::LTrim(openppp2_sub.substr(5u));
            if (peer_command == "status") {
                runtime::RuntimeSnapshot snapshot;
                {
                    std::lock_guard<std::mutex> scope(lock_);
                    snapshot = runtime_snapshot_;
                }
                for (const auto& line : tui::BuildPeerStatusLines(snapshot)) AppendLine(line.c_str());
                return;
            }
            if (peer_command.size() > 4u && peer_command.compare(0u, 4u, "set ") == 0) {
                const ppp::string args = ppp::LTrim(peer_command.substr(4u));
                const auto split = args.find(' ');
                if (split != ppp::string::npos) {
                    const ppp::string uuid = args.substr(0u, split);
                    const ppp::string priority = ppp::LTrim(args.substr(split + 1u));
                    if (priority == "ipv4-first" || priority == "ipv6-first" || priority == "relay-first") {
                        AppendLine(SetP2PPeerPriority(uuid, priority)
                            ? "Peer " + uuid + " priority set to " + priority
                            : "Peer priority update rejected (unknown UUID or invalid UUID)");
                        return;
                    }
                }
            }
            AppendLine("Usage: openppp2 peer status | openppp2 peer set <uuid> ipv4-first|ipv6-first|relay-first");
            return;
        }

        // ---- Telemetry sub-namespace ----
        static constexpr const char kTelNS[] = "telemetry";
        static constexpr std::size_t kTelNSLen = sizeof(kTelNS) - 1u;

        if (openppp2_sub.size() >= kTelNSLen &&
            0u == openppp2_sub.compare(0u, kTelNSLen, kTelNS) &&
            (openppp2_sub.size() == kTelNSLen || ' ' == openppp2_sub[kTelNSLen])) {

            auto emit_state = []() noexcept {
                ppp::string msg = "Telemetry filter: ";
                msg += ppp::telemetry::IsConsoleLogEnabled() ? "log=on " : "log=off ";
                msg += ppp::telemetry::IsConsoleMetricEnabled() ? "metric=on " : "metric=off ";
                msg += ppp::telemetry::IsConsoleSpanEnabled() ? "span=on " : "span=off ";
                msg += "level=" + std::to_string(ppp::telemetry::GetMinLevel());
                ConsoleUI::GetInstance().AppendLine(msg);
            };

            ppp::string tel_rest;
            if (openppp2_sub.size() > kTelNSLen) {
                tel_rest = ppp::LTrim(openppp2_sub.substr(kTelNSLen + 1u));
            }

            if (tel_rest.empty() || "status" == tel_rest) {
                emit_state();
                return;
            }

            if ("help" == tel_rest) {
                AppendLine("Telemetry commands:");
                AppendLine("  openppp2 telemetry                    - Show telemetry status");
                AppendLine("  openppp2 telemetry status             - Show telemetry status");
                AppendLine("  openppp2 telemetry help               - Show this help");
                AppendLine("  openppp2 telemetry log on|off|toggle  - Toggle console log filter");
                AppendLine("  openppp2 telemetry metric on|off|toggle - Toggle console metric filter");
                AppendLine("  openppp2 telemetry span on|off|toggle - Toggle console span filter");
                AppendLine("  openppp2 telemetry level 0|1|2|3      - Set telemetry verbosity threshold");
                AppendLine("  openppp2 telemetry all                - Enable all telemetry filters");
                AppendLine("  openppp2 telemetry quiet              - Disable all telemetry filters");
                AppendLine("  openppp2 telemetry clear              - Clear telemetry event buffer");
                return;
            }

            if ("all" == tel_rest) {
                ppp::telemetry::SetConsoleLogEnabled(true);
                ppp::telemetry::SetConsoleMetricEnabled(true);
                ppp::telemetry::SetConsoleSpanEnabled(true);
                emit_state();
                return;
            }

            if ("quiet" == tel_rest) {
                ppp::telemetry::SetConsoleLogEnabled(false);
                ppp::telemetry::SetConsoleMetricEnabled(false);
                ppp::telemetry::SetConsoleSpanEnabled(false);
                emit_state();
                return;
            }

            if ("clear" == tel_rest) {
                ClearTelemetryEventLines();
                AppendLine("Telemetry event buffer cleared.");
                return;
            }

            // Tokenize: expect "log|metric|span on|off|toggle" or "level N"
            ppp::vector<ppp::string> tokens;
            ppp::Tokenize(tel_rest, tokens, ppp::string(" "));

            // Known first-token check for targeted usage messages.
            auto is_known_tel_sub = [](const ppp::string& t) noexcept -> bool {
                return "log" == t || "metric" == t || "span" == t || "level" == t;
            };

            // Wrong number of arguments for a known sub-command → print usage
            // instead of falling through to the generic "Unknown" message.
            if (!tokens.empty() && is_known_tel_sub(tokens[0]) && 2u != tokens.size()) {
                if ("level" == tokens[0]) {
                    AppendLine("Usage: openppp2 telemetry level 0|1|2|3");
                } else {
                    AppendLine("Usage: openppp2 telemetry " + tokens[0] + " on|off|toggle");
                }
                return;
            }

            if (2u == tokens.size()) {
                if ("log" == tokens[0]) {
                    if ("on" == tokens[1]) {
                        ppp::telemetry::SetConsoleLogEnabled(true);
                    } elif ("off" == tokens[1]) {
                        ppp::telemetry::SetConsoleLogEnabled(false);
                    } elif ("toggle" == tokens[1]) {
                        ppp::telemetry::SetConsoleLogEnabled(!ppp::telemetry::IsConsoleLogEnabled());
                    } else {
                        AppendLine("Usage: openppp2 telemetry log on|off|toggle");
                        return;
                    }
                    emit_state();
                    return;
                }

                if ("metric" == tokens[0]) {
                    if ("on" == tokens[1]) {
                        ppp::telemetry::SetConsoleMetricEnabled(true);
                    } elif ("off" == tokens[1]) {
                        ppp::telemetry::SetConsoleMetricEnabled(false);
                    } elif ("toggle" == tokens[1]) {
                        ppp::telemetry::SetConsoleMetricEnabled(!ppp::telemetry::IsConsoleMetricEnabled());
                    } else {
                        AppendLine("Usage: openppp2 telemetry metric on|off|toggle");
                        return;
                    }
                    emit_state();
                    return;
                }

                if ("span" == tokens[0]) {
                    if ("on" == tokens[1]) {
                        ppp::telemetry::SetConsoleSpanEnabled(true);
                    } elif ("off" == tokens[1]) {
                        ppp::telemetry::SetConsoleSpanEnabled(false);
                    } elif ("toggle" == tokens[1]) {
                        ppp::telemetry::SetConsoleSpanEnabled(!ppp::telemetry::IsConsoleSpanEnabled());
                    } else {
                        AppendLine("Usage: openppp2 telemetry span on|off|toggle");
                        return;
                    }
                    emit_state();
                    return;
                }

                if ("level" == tokens[0]) {
                    if (1u == tokens[1].size() && tokens[1][0] >= '0' && tokens[1][0] <= '3') {
                        ppp::telemetry::SetMinLevel(tokens[1][0] - '0');
                        emit_state();
                        return;
                    }
                    AppendLine("Usage: openppp2 telemetry level 0|1|2|3");
                    return;
                }
            }

            AppendLine("Unknown telemetry sub-command: '" + tel_rest + "'");
            AppendLine("Type 'openppp2 telemetry help' for telemetry commands.");
            return;
        }

        AppendLine("Unknown openppp2 sub-command: '" + openppp2_sub + "'");
        AppendLine("Type 'openppp2 help' for available commands.");
        return;
    }

    AppendLine("Unknown command: '" + cmd + "'");
    AppendLine("Type 'openppp2 help' for available commands.");
}

// ---------------------------------------------------------------------------
// Input loop
// ---------------------------------------------------------------------------

void ConsoleUI::InputLoop() noexcept {
#if defined(_WIN32)
    while (running_.load(std::memory_order_acquire)) {
        if (0 == ::_kbhit()) {
            ppp::Sleep(15);
            continue;
        }

        int ch = ::_getch();
        if (0 == ch || 224 == ch) {
            // Extended / function key
            int key = ::_getch();
            if (72 == key) {            // Up arrow
                HandleHistoryUp();
            } else if (80 == key) {        // Down arrow
                HandleHistoryDown();
            } else if (75 == key) {        // Left arrow
                MoveCursorLeft();
            } else if (77 == key) {        // Right arrow
                MoveCursorRight();
            } else if (71 == key) {        // Home — scroll info to top
                ScrollInfoBy(-999999);
            } else if (79 == key) {        // End — scroll info to bottom
                ScrollInfoBy(999999);
            } else if (83 == key) {        // Delete
                EraseAtCursor();
            } else if (73 == key) {        // PageUp — scroll cmd up
                ScrollCmdPage(1);
            } else if (81 == key) {        // PageDown — scroll cmd down
                ScrollCmdPage(-1);
            }
            continue;
        }

        if (13 == ch) {             // Enter
            HandleEnter();
            continue;
        }

        if (8 == ch) {              // Backspace
            EraseBeforeCursor();
            continue;
        }

        if (1 == ch) {              // Ctrl+A
            MoveCursorLineStart();
            continue;
        }

        if (5 == ch) {              // Ctrl+E
            MoveCursorLineEnd();
            continue;
        }

        if (32 <= ch && 126 >= ch) {
            InsertInputChar(static_cast<char>(ch));
        }
    }

#else  // POSIX

    while (running_.load(std::memory_order_acquire)) {
        // Use poll() with a 100 ms timeout instead of O_NONBLOCK + busy-wait.
        // This avoids PTY-specific issues on WSL, tmux, and screen where
        // O_NONBLOCK can spuriously produce EIO or EAGAIN.
        struct pollfd pfd;
        pfd.fd     = STDIN_FILENO;
        pfd.events = POLLIN;

        int pr = ::poll(&pfd, 1, 100);
        if (0 > pr) {
            if (EINTR == errno) {
                continue;
            }
            break;  // Hard error
        }
        if (0 == pr) {
            continue;  // Timeout — loop back and check running_
        }
        if (0 == (pfd.revents & POLLIN)) {
            continue;
        }

        char ch = '\0';
        ssize_t n = ::read(STDIN_FILENO, &ch, 1u);
        if (1 != n) {
            continue;  // Transient: spurious wake or EIO — retry.
        }

        // Ctrl+A / Ctrl+E
        if ('\x01' == ch) { MoveCursorLineStart(); continue; }
        if ('\x05' == ch) { MoveCursorLineEnd();   continue; }

        if ('\r' == ch || '\n' == ch) {
            HandleEnter();
            continue;
        }

        if (127 == static_cast<unsigned char>(ch) || 8 == static_cast<unsigned char>(ch)) {
            EraseBeforeCursor();
            continue;
        }

        if (27 == static_cast<unsigned char>(ch)) {
            // ESC sequence reader
            char seq[16] = {'\0'};
            int  seq_len = 0;

            for (; seq_len < 15; ++seq_len) {
                ssize_t rn = ::read(STDIN_FILENO, &seq[seq_len], 1u);
                if (0 >= rn) {
                    break;
                }
                char c = seq[seq_len];
                if (seq_len == 0 && 'O' == c) {
                    continue;
                }
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || '~' == c) {
                    ++seq_len;
                    break;
                }
            }

            ppp::string key(seq, static_cast<std::size_t>(std::max(0, seq_len)));

            if ("[A" == key || "OA" == key) {       // Up
                HandleHistoryUp();
            } else if ("[B" == key || "OB" == key) {   // Down
                HandleHistoryDown();
            } else if ("[C" == key || "OC" == key) {   // Right
                MoveCursorRight();
            } else if ("[D" == key || "OD" == key) {   // Left
                MoveCursorLeft();
            } else if ("[H" == key || "[1~" == key ||  // Home — scroll info to top
                    "[7~" == key || "OH" == key) {
                ScrollInfoBy(-999999);
            } else if ("[F" == key || "[4~" == key ||  // End — scroll info to bottom
                    "[8~" == key || "OF" == key) {
                ScrollInfoBy(999999);
            } else if ("[3~" == key) {                 // Delete
                EraseAtCursor();
            } else if ("[5~" == key) {                 // PageUp — scroll cmd up
                ScrollCmdPage(1);
            } else if ("[6~" == key) {                 // PageDown — scroll cmd down
                ScrollCmdPage(-1);
            }
            continue;
        }

        if (32 <= static_cast<unsigned char>(ch) && 126 >= static_cast<unsigned char>(ch)) {
            InsertInputChar(ch);
        }
    }

#endif  // POSIX
}

// ---------------------------------------------------------------------------
// Terminal helpers
// ---------------------------------------------------------------------------

bool ConsoleUI::EnableVirtualTerminal() noexcept {
#if defined(_WIN32)
    // UTF-8 is needed only when Unicode UI glyphs are explicitly enabled.
    if (UseUnicodeUiGlyphs()) {
        ::SetConsoleOutputCP(CP_UTF8);
    }

    HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (NULLPTR == h || INVALID_HANDLE_VALUE == h) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return false;
    }

    DWORD mode = 0;
    if (!::GetConsoleMode(h, &mode)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return false;
    }

    if (0u == (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        if (!::SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
            return false;
        }
    }

    return true;
#else
    return true;
#endif
}

bool ConsoleUI::PrepareInputTerminal() noexcept {
#if defined(_WIN32)
    // Disable ENABLE_ECHO_INPUT and ENABLE_LINE_INPUT on stdin so that
    // _kbhit()/_getch() deliver raw keystrokes without echoing them to the
    // screen (which would corrupt the TUI frame).
    win_stdin_handle_  = ::GetStdHandle(STD_INPUT_HANDLE);
    win_in_mode_saved_ = false;

    if (NULLPTR != win_stdin_handle_ && INVALID_HANDLE_VALUE != win_stdin_handle_) {
        DWORD mode = 0;
        if (::GetConsoleMode(static_cast<HANDLE>(win_stdin_handle_), &mode)) {
            win_original_in_mode_ = mode;
            win_in_mode_saved_    = true;
            ::SetConsoleMode(static_cast<HANDLE>(win_stdin_handle_),
                mode & ~(DWORD)(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
        }
    }

    return true;
#else
    if (terminal_ready_) {
        return true;
    }

    if (0 != ::tcgetattr(STDIN_FILENO, &terminal_original_)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return false;
    }

    struct termios raw = terminal_original_;
    raw.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL));
    raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON));
    raw.c_cc[VMIN]  = 1;   // Wait for at least one byte
    raw.c_cc[VTIME] = 0;   // No inter-byte timeout

    if (0 != ::tcsetattr(STDIN_FILENO, TCSANOW, &raw)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return false;
    }

    // Non-blocking is NOT set on stdin.  Instead the input loop uses
    // poll() with a timeout, which avoids PTY-specific issues that
    // O_NONBLOCK can trigger on some terminal emulators (WSL, tmux,
    // screen) where read() spuriously returns EIO or EAGAIN even
    // when data is available.

    terminal_ready_ = true;
    return true;
#endif
}

void ConsoleUI::RestoreInputTerminal() noexcept {
#if defined(_WIN32)
    // Restore the original stdin console mode saved by PrepareInputTerminal().
    if (win_in_mode_saved_ &&
        NULLPTR != win_stdin_handle_ &&
        INVALID_HANDLE_VALUE != win_stdin_handle_) {
        ::SetConsoleMode(static_cast<HANDLE>(win_stdin_handle_), win_original_in_mode_);
    }

    win_stdin_handle_  = NULLPTR;
    win_in_mode_saved_ = false;
    return;
#else
    if (!terminal_ready_) {
        return;
    }

    if (0 <= terminal_flags_) {
        ::fcntl(STDIN_FILENO, F_SETFL, terminal_flags_);
    }

    ::tcsetattr(STDIN_FILENO, TCSANOW, &terminal_original_);
    terminal_ready_  = false;
    terminal_flags_  = -1;
#endif
}

} // namespace ppp::app
