package auxiliary

import (
	"log"
	"os"
)

var _LOG_ERROR *log.Logger = log.New(os.Stdout, "[ERROR]", log.LstdFlags|log.Lshortfile)  /* log.Ldate | log.Ltime | log.Lshortfile */
var _LOG_INFO *log.Logger = log.New(os.Stdout, "[INFO]", log.LstdFlags|log.Lshortfile)    /* log.Ldate | log.Ltime | log.Lshortfile */
var _LOG_WARN *log.Logger = log.New(os.Stdout, "[WARN]", log.LstdFlags|log.Lshortfile)    /* log.Ldate | log.Ltime | log.Lshortfile */
var _LOG_EDEBUG *log.Logger = log.New(os.Stdout, "[DEBUG]", log.LstdFlags|log.Lshortfile) /* log.Ldate | log.Ltime | log.Lshortfile */

func LOG_ERROR() *log.Logger {
	return _LOG_ERROR
}

func LOG_INFO() *log.Logger {
	return _LOG_INFO
}

func LOG_WARN() *log.Logger {
	return _LOG_WARN
}

func LOG_DEBUG() *log.Logger {
	return _LOG_EDEBUG
}
