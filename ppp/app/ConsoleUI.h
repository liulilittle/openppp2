/**
 * @file ConsoleUI.h
 * @brief Full-screen box-drawing TUI for PPP PRIVATE NETWORK(TM) 2.
 *
 * @details
 * The terminal frame is divided into the following sections:
 *
 * @code
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ PageUp/PageDown: Scroll command input/output   PPP PRIVATE NETWORK™ 2│
 * │ Home/End       : Scroll openppp2 info                                │
 * │          ___  ____  _____ _   _ ____  ____  ____ ____               │
 * │         / _ \|  _ \| ____| \ | |  _ \|  _ \|  _ \___ \             │
 * │        | | | | |_) |  _| |  \| | |_) | |_) | |_) |__) |            │
 * │        | |_| |  __/| |___| |\  |  __/|  __/|  __// __/             │
 * │         \___/|_|   |_____|_| \_|_|   |_|   |_|  |_____|            │
 * │                                                                      │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │  [Info section — VPN status snapshot, scrollable with Home / End]   │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │  [Cmd section — command history & output, PageUp / PageDown scroll] │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │  > [input line or placeholder text]                                  │
 * ├──────────────────────────────────────┬───────────────────────────────┤
 * │  [INFO] error description (Ns ago)   │  VPN: state  ↑ tx/s  ↓ rx/s │
 * └──────────────────────────────────────┴───────────────────────────────┘
 * @endcode
 *
 * @note When stdout is not attached to a terminal (isatty returns 0), the TUI is
 *       not started.  Basic environment information is printed to stdout directly
 *       and the process continues normally without an interactive interface.
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/app/runtime/RuntimeSnapshot.h>

#if !defined(_WIN32)
#include <termios.h>
#endif

namespace ppp::app {

/**
 * @brief Process-wide singleton that manages the full-screen console TUI.
 *
 * All public methods are safe to call concurrently from any thread.
 * Internal mutable state is protected by a single recursive-safe mutex.
 */
class ConsoleUI final {
public:
    using P2PPriorityHandler = std::function<bool(const ppp::string&)>;
    using P2PPeerPriorityHandler = std::function<bool(const ppp::string&, const ppp::string&)>;

    void                    SetP2PPriorityHandler(P2PPriorityHandler handler) noexcept;
    void                    SetP2PPeerPriorityHandler(P2PPeerPriorityHandler handler) noexcept;
    bool                    SetP2PPriority(const ppp::string& priority) noexcept;
    bool                    SetP2PPeerPriority(const ppp::string& peer_uuid, const ppp::string& priority) noexcept;
    ppp::string             GetP2PPriority() noexcept;

    /**
     * @brief Checks whether the TUI should be enabled for this process.
     *
     * Tests whether stdout is connected to a real terminal.  When the process
     * output is redirected to a file or pipe, this returns false and the caller
     * must skip Start() and fall back to plain text printing.
     *
     * @return True when stdout is a terminal, false when redirected.
     */
    static bool             ShouldEnable() noexcept;

    /**
     * @brief Returns the process-wide singleton instance.
     * @return Reference to the singleton ConsoleUI object.
     */
    static ConsoleUI&       GetInstance() noexcept;

public:
    /**
     * @brief Starts the render and input worker threads.
     *
     * @return True when both threads started successfully.
     *         False on terminal-setup failure.
     * @note   Always call ShouldEnable() before Start().
     */
    bool                    Start() noexcept;

    /**
     * @brief Requests worker threads to stop and blocks until they exit.
     *
     * Restores the original terminal state and re-enables the cursor.
     * Safe to call multiple times or when Start() was never called.
     */
    void                    Stop() noexcept;

public:
    /**
     * @brief Updates the VPN-state/speed text shown in the status bar.
     *
     * The text is parsed for keywords ("established", "disconnect", etc.) to
     * maintain a human-readable state label, and is forwarded to the right
     * panel of the status bar.
     *
     * @param status_text Free-form string describing state and throughput.
     */
    void                    UpdateStatus(const ppp::string& status_text) noexcept;

    /**
     * @brief Appends one line to the command-output ring buffer.
     *
     * Lines beyond kMaxCmdLines are discarded from the front.
     *
     * @param line Text to append (truncated at display if wider than terminal).
     */
    void                    AppendLine(const ppp::string& line) noexcept;

    /**
     * @brief Replaces the VPN info section content with a new snapshot.
     *
     * The entire previous content is discarded and replaced atomically.
     * The info scroll offset is reset to 0 (top) on each call.
     *
     * @param lines New set of lines for the info section.
     */
    void                    SetInfoLines(const ppp::vector<ppp::string>& lines) noexcept;
    void                    SetRuntimeSnapshot(const runtime::RuntimeSnapshot& snapshot) noexcept;

    /**
     * @brief Replaces the telemetry info section content.
     *
     * In two-column mode these lines are shown in the right column.
     * In single-column mode they are appended after info_lines_.
     *
     * @param lines New set of telemetry lines.
     */
    void                    SetTelemetryLines(const ppp::vector<ppp::string>& lines) noexcept;

    /**
     * @brief Returns true when the TUI render and input threads are running.
     *
     * Safe to call from any thread (uses an atomic load).  Returns false
     * before Start() or after Stop().
     */
    static bool             IsRunning() noexcept;

    /**
     * @brief Appends one telemetry event line to the internal ring buffer.
     *
     * ANSI escape codes and trailing newlines are stripped before storage.
     * The line is displayed in the telemetry panel during the next render
     * frame.  Thread-safe — may be called from the telemetry backend thread.
     *
     * @param line  Pre-formatted telemetry line (may contain ANSI escapes).
     */
    void                    AppendTelemetryEventLine(const char* line) noexcept;

    /**
     * @brief Clears all telemetry event lines from the ring buffer.
     */
    void                    ClearTelemetryEventLines() noexcept;

private:
    ConsoleUI() = default;
    ~ConsoleUI() = default;
    ConsoleUI(const ConsoleUI&)             = delete;
    ConsoleUI& operator=(const ConsoleUI&)  = delete;

    // -----------------------------------------------------------------------
    // Worker-thread entry points
    // -----------------------------------------------------------------------

    /** @brief Render loop: fires at ~10 Hz and calls RenderFrame(). */
    void                    RenderLoop() noexcept;
    /** @brief Input loop: reads keyboard events and dispatches handlers. */
    void                    InputLoop() noexcept;

    // -----------------------------------------------------------------------
    // Core frame builder
    // -----------------------------------------------------------------------

    /** @brief Builds and writes one complete terminal frame to stdout. */
    void                    RenderFrame() noexcept;
    /** @brief Drains status_queue_ and updates vpn_state_text_ / speed_text_. */
    void                    DrainStatusQueue() noexcept;

    /**
     * @brief Marks the UI as dirty so the render loop will redraw on its
     *        next tick.  Called by every mutator on the data model.
     */
    void                    MarkDirty() noexcept;

    /**
     * @brief Enters the terminal alternate screen buffer (\x1b[?1049h).
     *
     * While in the alternate buffer, all output is isolated from the
     * user's original shell scrollback.  On Stop() the paired
     * LeaveAlternateScreen() restores the previous buffer contents
     * verbatim, so the console returns to the exact state it was in
     * before the TUI launched.
     */
    void                    EnterAlternateScreen() noexcept;
    /** @brief Leaves the terminal alternate screen buffer (\x1b[?1049l). */
    void                    LeaveAlternateScreen() noexcept;

    // -----------------------------------------------------------------------
    // Input editing handlers (all called from InputLoop)
    // -----------------------------------------------------------------------

    void                    HandleEnter() noexcept;
    void                    HandleHistoryUp() noexcept;
    void                    HandleHistoryDown() noexcept;
    void                    InsertInputChar(char ch) noexcept;
    void                    MoveCursorLeft() noexcept;
    void                    MoveCursorRight() noexcept;
    void                    MoveCursorLineStart() noexcept;
    void                    MoveCursorLineEnd() noexcept;
    void                    EraseBeforeCursor() noexcept;
    void                    EraseAtCursor() noexcept;

    // -----------------------------------------------------------------------
    // Command execution
    // -----------------------------------------------------------------------

    /**
     * @brief Dispatches a complete command line to built-in command execution.
     * @param command_line Raw input string (trimmed by caller).
     */
    void                    ExecuteCommand(const ppp::string& command_line) noexcept;

    // -----------------------------------------------------------------------
    // Scroll handlers
    // -----------------------------------------------------------------------

    /** @brief Scrolls the info section by delta display lines (negative = up). */
    void                    ScrollInfoBy(int delta) noexcept;
    /** @brief Scrolls the info section by one visible page. direction>0 = up. */
    void                    ScrollInfoPage(int direction) noexcept;
    /** @brief Scrolls the cmd section by delta lines (negative = down toward newest). */
    void                    ScrollCmdBy(int delta) noexcept;
    /** @brief Scrolls the cmd section by one visible page. direction>0 = up. */
    void                    ScrollCmdPage(int direction) noexcept;

    // -----------------------------------------------------------------------
    // Terminal setup helpers
    // -----------------------------------------------------------------------

    /** @brief Enables VT100/ANSI virtual terminal processing on Windows. */
    bool                    EnableVirtualTerminal() noexcept;
    /** @brief Puts stdin into raw non-blocking mode on POSIX. */
    bool                    PrepareInputTerminal() noexcept;
    /** @brief Restores the original terminal mode saved by PrepareInputTerminal(). */
    void                    RestoreInputTerminal() noexcept;

    // -----------------------------------------------------------------------
    // Frame-building helpers (static — no lock required)
    // -----------------------------------------------------------------------

    /**
     * @brief Returns a string of (count) horizontal box-draw characters (─).
     * @param count Number of characters to repeat.
     */
    static ppp::string      RepeatHoriz(int count) noexcept;

    /**
     * @brief Builds one full-width box content row.
     *
     * Format: │<content padded to (width-2) display columns>│\n
     *
     * @param content  Text to display (pure ASCII assumed for width calculation).
     * @param width    Total display width including both │ borders.
     */
    static ppp::string      BoxContentRow(const ppp::string& content, int width) noexcept;

    /**
     * @brief Builds a box row split into left and right panels.
     *
     * Format: │<left>│<right>│\n  (split position in display columns from left).
     *
     * @param left   Content for left panel.
     * @param right  Content for right panel.
     * @param width  Total display width.
     * @param split  Display-column position of the vertical divider.
     */
    static ppp::string      BoxSplitRow(
                                const ppp::string& left,
                                const ppp::string& right,
                                int width,
                                int split) noexcept;

    /** @brief Full-width separator: ├────────────────────┤\n */
    static ppp::string      BoxSepRow(int width) noexcept;

    /** @brief Split separator: ├─────────┬──────────┤\n */
    static ppp::string      BoxSplitSepRow(int width, int split) noexcept;

    /** @brief Bottom border: └────────────────────┘\n */
    static ppp::string      BoxBotRow(int width) noexcept;

    /** @brief Split bottom border: └─────────┴──────────┘\n */
    static ppp::string      BoxBotSplitRow(int width, int split) noexcept;

    /**
     * @brief Renders one ANSI-colored ASCII-art line centered inside the box.
     *
     * Characters at positions [0, kArtSplitCol) are rendered in dark-gray,
     * characters from kArtSplitCol onward are rendered in bright-white.
     *
     * @param raw        Pure ASCII art line (no ANSI escapes).
     * @param inner_width Display columns available between the two │ borders.
     * @param use_color  When false, omits ANSI codes (plain text fallback).
     */
    static ppp::string      RenderArtLine(
                                const ppp::string& raw,
                                int inner_width,
                                bool use_color) noexcept;

    /**
     * @brief Truncates or right-pads a string to exactly display_width columns.
     *
     * For strings longer than display_width, the last three printable
     * columns are replaced with "...".
     *
     * @param s             Input string (pure ASCII; ANSI codes are transparent).
     * @param display_width Target display column count.
     */
    static ppp::string      FitWidth(const ppp::string& s, int display_width) noexcept;

    /**
     * @brief Builds the editor display string with a viewport-clipping window.
     *
     * The caller-selected cursor byte is rendered as a synthetic white
     * block (ANSI reverse-video) embedded inside the returned string so the
     * real terminal cursor can remain permanently hidden.  This eliminates
     * cursor flicker that would otherwise arise from cyclic show/hide
     * sequences on each render.
     *
     * Handles overflow indicators (<  >) when the text is wider than available
     * columns, and computes the screen cursor column for diagnostic use.
     *
     * @param prompt        Fixed prefix string (e.g. "> ").
     * @param input         Current input buffer.
     * @param cursor_pos    Byte position of the text cursor within input.
     * @param width         Total display width for the editor area.
     * @param use_color     Whether to emit ANSI sequences for the cursor block.
     * @param cursor_column Output: zero-indexed display column of the cursor.
     * @return              Editor line content (without │ borders).
     */
    static ppp::string      BuildEditorLine(
                                const ppp::string& prompt,
                                const ppp::string& input,
                                std::size_t cursor_pos,
                                int width,
                                bool use_color,
                                int& cursor_column) noexcept;

    /**
     * @brief Formats a relative timestamp as "Ns ago" or "n/a".
     * @param now_ms   Current monotonic time in milliseconds.
     * @param then_ms  Reference monotonic time in milliseconds.
     * @return Human-readable age string.
     */
    static ppp::string      FormatAge(uint64_t now_ms, uint64_t then_ms) noexcept;

private:
    // -----------------------------------------------------------------------
    // Threading state
    // -----------------------------------------------------------------------

    /** @brief Set to true by Start(), false by Stop(); guards thread lifetime. */
    std::atomic<bool>           running_{false};
    std::thread                 render_thread_;
    std::thread                 input_thread_;

    /**
     * @brief Mutex used exclusively as the condition-variable predicate lock.
     *
     * Kept separate from lock_ so that MarkDirty() (called from any thread)
     * can notify render_cv_ without acquiring the heavy data-model lock_.
     */
    std::mutex                  render_cv_mutex_;

    /**
     * @brief Condition variable that wakes the render thread on dirty/stop.
     *
     * Replaces the unconditional ppp::Sleep(50) poll loop.  The render thread
     * waits on this CV with a 100 ms timeout; any mutator that calls MarkDirty()
     * notifies it immediately.  Stop() also notifies to unblock the thread.
     */
    std::condition_variable     render_cv_;

    /**
     * @brief Last monotonic millisecond timestamp when telemetry woke renderer.
     *
     * Telemetry events may arrive in large bursts; event ingestion sets dirty_
     * for every line but only notifies render_cv_ at a bounded cadence.
     */
    std::atomic<uint64_t>        last_telemetry_dirty_notify_ms_{0};

    // -----------------------------------------------------------------------
    // Shared mutable state (all accesses must hold lock_)
    // -----------------------------------------------------------------------

    /** @brief Guards all mutable fields below. */
    std::mutex                  lock_;

    /** @brief VPN info snapshot displayed in the info section. */
    ppp::vector<ppp::string>    info_lines_;
    runtime::RuntimeSnapshot    runtime_snapshot_;
    ppp::string                 p2p_priority_ = "ipv6-first";
    P2PPriorityHandler          p2p_priority_handler_;
    P2PPeerPriorityHandler      p2p_peer_priority_handler_;
    /** @brief Telemetry lines displayed in the right column (two-column mode). */
    ppp::vector<ppp::string>    telemetry_lines_;
    /** @brief Telemetry event stream ring buffer (newest at back). */
    std::deque<ppp::string>     telemetry_event_lines_;
    /**
     * @brief Info section scroll offset.
     *
     * 0 = show the first info lines (top).
     * Increases to scroll further down into the info content.
     */
    int                         info_scroll_    = 0;

    /** @brief Command output ring buffer (newest at the back). */
    std::deque<ppp::string>     cmd_lines_;
    /**
     * @brief Cmd section scroll offset.
     *
     * 0 = pinned to bottom (newest content visible).
     * Increases to scroll up toward older content.
     */
    int                         cmd_scroll_     = 0;

    /** @brief Queue of status strings awaiting drain into vpn_state_text_. */
    std::queue<ppp::string>     status_queue_;
    /** @brief Human-readable VPN state (e.g. "Connected", "Disconnected"). */
    ppp::string                 vpn_state_text_;
    /** @brief Speed text extracted from last UpdateStatus call. */
    ppp::string                 speed_text_;

    /** @brief Current input buffer (edited by the input loop). */
    ppp::string                 input_buffer_;
    /** @brief Byte offset of the text cursor within input_buffer_. */
    std::size_t                 input_cursor_   = 0;

    /** @brief Command history ring buffer (oldest at front). */
    std::deque<ppp::string>     history_;
    /** @brief Navigation index into history_ (-1 when not navigating). */
    int                         history_index_  = -1;
    /** @brief Saved input text when history navigation began. */
    ppp::string                 history_edit_backup_;

    // -----------------------------------------------------------------------
    // Non-guarded state (written by Start/Stop; read by render/input threads)
    // -----------------------------------------------------------------------

    /** @brief True when ANSI/VT100 escape codes are supported on this terminal. */
    bool                        vt_enabled_     = false;

    /**
     * @brief Dirty flag.
     *
     * Set by any public mutator (AppendLine, UpdateStatus, SetInfoLines,
     * Insert*, Move*, Erase*, Scroll*, HandleEnter, etc.) and cleared by
     * RenderFrame() once the frame has been flushed to stdout.  The render
     * thread skips redraws when both this flag and the forced-redraw flag
     * are false, eliminating unnecessary writes and terminal flicker.
     */
    std::atomic<bool>           dirty_{true};

    /**
     * @brief Forced-redraw flag.
     *
     * Set when the cached terminal dimensions change between render passes
     * (window resize) or on the very first frame after Start().  A forced
     * redraw writes the full \x1b[2J clear sequence before the frame to
     * guarantee no stale content from the previous size remains.
     */
    std::atomic<bool>           force_redraw_{true};

    /** @brief Cached terminal width from the most recent render pass. */
    int                         last_width_     = 0;
    /** @brief Cached terminal height from the most recent render pass. */
    int                         last_height_    = 0;

    // -----------------------------------------------------------------------
    // Saved terminal state (restored on Stop)
    // -----------------------------------------------------------------------

    /** @brief True once Start() has successfully entered the alt-screen buffer. */
    bool                        altscreen_entered_ = false;

#if defined(_WIN32)
    /** @brief Handle to stdout saved at Start() for state restoration. */
    void*                       win_stdout_handle_ = NULLPTR;
    /** @brief Original console output mode restored by Stop(). */
    unsigned long               win_original_out_mode_  = 0;
    /** @brief True if win_original_out_mode_ is valid. */
    bool                        win_out_mode_saved_     = false;
    /** @brief Original cursor visibility restored by Stop(). */
    bool                        win_cursor_visible_     = true;
    /** @brief True if win_cursor_visible_ is valid. */
    bool                        win_cursor_saved_       = false;
    /** @brief Original console output code page restored by Stop(). */
    unsigned int                win_original_output_cp_ = 0;
    /** @brief True if win_original_output_cp_ is valid. */
    bool                        win_output_cp_saved_    = false;

    /**
     * @brief Handle to stdin used by PrepareInputTerminal() / RestoreInputTerminal().
     *
     * On Windows, PrepareInputTerminal() disables ENABLE_ECHO_INPUT and
     * ENABLE_LINE_INPUT so that _kbhit() / _getch() receive raw keystrokes
     * without echoing them to the screen.  RestoreInputTerminal() restores
     * the original mode from win_original_in_mode_.
     */
    void*                       win_stdin_handle_       = NULLPTR;
    /** @brief Original stdin console mode saved by PrepareInputTerminal(). */
    unsigned long               win_original_in_mode_   = 0;
    /** @brief True if win_original_in_mode_ is valid. */
    bool                        win_in_mode_saved_      = false;
#endif

    // -----------------------------------------------------------------------
    // Ring-buffer capacity limits
    // -----------------------------------------------------------------------

    /** @brief Maximum number of lines retained in the command output buffer. */
    static constexpr int        kMaxCmdLines                = 10000;
    /** @brief Maximum number of telemetry event lines in the ring buffer. */
    static constexpr int        kMaxTelemetryEventLines     = 500;
    /** @brief Minimum interval between telemetry-triggered render wakeups. */
    static constexpr uint64_t   kTelemetryDirtyNotifyIntervalMs = 100;
    /** @brief Maximum number of history entries. */
    static constexpr int        kMaxHistoryEntries  = 200;
    /**
     * @brief Display-column split point between OPEN and PPP2 in ASCII art.
     *
     * Columns [0, kArtSplitCol) receive dark-gray color; the remainder are
     * bright-white.
     */
    static constexpr int        kArtSplitCol        = 24;

#if !defined(_WIN32)
    /** @brief True after PrepareInputTerminal() succeeds. */
    bool                        terminal_ready_     = false;
    /** @brief Saved terminal attributes restored by RestoreInputTerminal(). */
    struct termios              terminal_original_{};
    /** @brief Saved file-descriptor flags restored by RestoreInputTerminal(). */
    int                         terminal_flags_     = -1;
#endif
};

} // namespace ppp::app
