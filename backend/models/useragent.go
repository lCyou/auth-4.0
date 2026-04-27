package models

import (
	"time"
)

type contextKey string
const OsContextKey contextKey = "os"

// type AccessLog struct {
//     Timestamp time.Time `json:"timestamp"`
//     Latency   int64     `json:"latency"`
//     Path      string    `json:"path"`
//     OS        string    `json:"os"`
// }

type AccessLog struct {
    Timestamp time.Time 
    Latency   int64     
    Path      string    
    OS        string    
}