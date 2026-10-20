package service

// Key watch was taken out of the build in 0.8.1: Microsoft Defender flagged
// the 0.8.0 build as password-stealing malware, a false positive pending a
// report to Microsoft. internal/secrets is kept but no longer built in; this
// file's 0.8.0 contents return with it once the detection is resolved.
