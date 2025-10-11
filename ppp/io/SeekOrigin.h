#pragma once

namespace ppp {
    namespace io {
        enum SeekOrigin {
            /// <summary>Specifies the beginning of a stream.</summary>
            Begin,
            /// <summary>Specifies the current position within a stream.</summary>
            Current,
            /// <summary>Specifies the end of a stream.</summary>
            End
        };
    }
}