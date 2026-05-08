function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B"
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KiB"
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MiB"
    return (bytes / 1073741824).toFixed(1) + " GiB"
}

// Join a directory and a filename with the appropriate separator.
// Preserves an existing trailing separator on dir (e.g. Windows "E:\");
// otherwise inserts a forward slash, which both Windows and POSIX
// file APIs accept.
function joinPath(dir, file) {
    if (!dir || dir.length === 0) return file
    var last = dir.charAt(dir.length - 1)
    if (last === '/' || last === '\\') return dir + file
    return dir + '/' + file
}
