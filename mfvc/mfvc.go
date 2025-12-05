package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ripemd160"
)

// FileInfo stores file metadata and hash
type FileInfo struct {
	Path        string    `json:"path"`
	Hash        string    `json:"hash"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
	Permissions string    `json:"permissions"`
}

// Metadata stores the complete state of a folder
type Metadata struct {
	RootHash      string     `json:"root_hash"`
	FolderPath    string     `json:"folder_path"`
	CreatedAt     time.Time  `json:"created_at"`
	FileCount     int        `json:"file_count"`
	TotalSize     int64      `json:"total_size"`
	Files         []FileInfo `json:"files"`
	Algorithm     string     `json:"algorithm"`
	Version       string     `json:"version"`
	ExcludedPaths []string   `json:"excluded_paths,omitempty"`
}

// ChangeResult stores detected changes
type ChangeResult struct {
	Added     []FileInfo `json:"added"`
	Modified  []FileInfo `json:"modified"`
	Deleted   []FileInfo `json:"deleted"`
	Unchanged []FileInfo `json:"unchanged"`
	RootMatch bool       `json:"root_match"`
	Message   string     `json:"message"`
}

// DNSRecord stores DNS-based hash information
type DNSRecord struct {
	Hash           string    `json:"hash"`
	Timestamp      time.Time `json:"timestamp"`
	Source         string    `json:"source"`
	Valid          bool      `json:"valid"`
	ExcludedPaths  []string  `json:"excluded_paths,omitempty"`
	ExcludedCount  int       `json:"excluded_count,omitempty"`
}

// VerificationResult stores complete verification results
type VerificationResult struct {
	ServerURL        string        `json:"server_url"`
	Domain           string        `json:"domain"`
	VerificationDate time.Time     `json:"verification_date"`
	OriginalMetadata *Metadata     `json:"original_metadata"`
	CurrentFiles     []FileInfo    `json:"current_files"`
	Changes          *ChangeResult `json:"changes"`
	CalculatedRoot   string        `json:"calculated_root"`
	DNSRecord        *DNSRecord    `json:"dns_record,omitempty"`
	DNSMatch         bool          `json:"dns_match,omitempty"`
	RootMatch        bool          `json:"root_match"`
	Success          bool          `json:"success"`
	ErrorMessage     string        `json:"error_message,omitempty"`
	ExcludedInfo     string        `json:"excluded_info,omitempty"`
}

// DownloadResult stores download operation results
type DownloadResult struct {
	Success       bool      `json:"success"`
	Timestamp     time.Time `json:"timestamp"`
	Files         []string  `json:"files"`
	TotalSize     int64     `json:"total_size"`
	ErrorMessages []string  `json:"error_messages,omitempty"`
}

// Constants
const (
	Version   = "0.3.0"
	Algorithm = "RIPEMD-160"
)

// Helper function to check if string is hex
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Calculate RIPEMD-160 hash for byte array
func calculateRIPEMD160(data []byte) string {
	hasher := ripemd160.New()
	hasher.Write(data)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// Download file from URL and save to local path
func downloadFile(url string, filepath string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filepath, err)
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s for %s", resp.Status, url)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %v", filepath, err)
	}

	return nil
}

// Download proof files from server
func downloadProofs(serverURL string) *DownloadResult {
	result := &DownloadResult{
		Success:       false,
		Timestamp:     time.Now().UTC(),
		Files:         []string{},
		ErrorMessages: []string{},
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("DOWNLOADING PROOF FILES")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Server URL: %s\n", serverURL)
	fmt.Println()

	// Define the files to download with their local names
	filesToDownload := []struct {
		remotePath string
		localName  string
	}{
		{".well-known/mfv/merkle_metadata.json", "merkle_metadata.json"},
		{".well-known/mfv/merkle_metadata.json.ots", "merkle_metadata.json.ots"},
		{".well-known/mfv/dns.txt", "dns.txt"},
		{".well-known/mfv/dns.txt.ots", "dns.txt.ots"},
		{".well-known/merkle-metadata.json", "merkle_metadata.json"},
		{".well-known/merkle-metadata.json.ots", "merkle_metadata.json.ots"},
		{".well-known/dns.txt", "dns.txt"},
		{".well-known/dns.txt.ots", "dns.txt.ots"},
	}

	successCount := 0
	var totalSize int64

	for _, file := range filesToDownload {
		// Skip if we already have this file
		alreadyDownloaded := false
		for _, downloaded := range result.Files {
			if downloaded == file.localName {
				alreadyDownloaded = true
				break
			}
		}
		if alreadyDownloaded {
			continue
		}

		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(serverURL, "/"), file.remotePath)
		
		fmt.Printf("Trying: %s\n", url)

		// Try to download
		if err := downloadFile(url, file.localName); err == nil {
			// Get file size
			if info, err := os.Stat(file.localName); err == nil {
				totalSize += info.Size()
			}

			result.Files = append(result.Files, file.localName)
			successCount++
			fmt.Printf("  ✓ Downloaded: %s\n", file.localName)
		} else {
			fmt.Printf("  ✗ Failed: %v\n", err)
		}
	}

	// Check what we got
	result.TotalSize = totalSize
	result.Success = successCount > 0

	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Download Summary:\n")
	fmt.Printf("  Successfully downloaded: %d files\n", successCount)
	fmt.Printf("  Total size: %s\n", formatBytes(totalSize))
	
	if len(result.Files) > 0 {
		fmt.Printf("  Files saved to current directory:\n")
		for _, file := range result.Files {
			fmt.Printf("    - %s\n", file)
		}
	} else {
		fmt.Printf("  No files were downloaded. Please check the server configuration.\n")
		fmt.Printf("  Expected files in: .well-known/mfv/ or .well-known/\n")
	}

	fmt.Println(strings.Repeat("=", 70))
	return result
}

// Fetch metadata from server
func fetchMetadata(serverURL string) (*Metadata, error) {
	possiblePaths := []string{
		".well-known/mfv/merkle_metadata.json",
		".well-known/merkle-metadata.json",
		"merkle_metadata.json",
	}

	var lastError error
	for _, path := range possiblePaths {
		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(serverURL, "/"), path)
		
		resp, err := http.Get(url)
		if err != nil {
			lastError = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var metadata Metadata
			if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
				return nil, fmt.Errorf("failed to parse metadata: %v", err)
			}
			return &metadata, nil
		}
	}

	return nil, fmt.Errorf("metadata not found. Last error: %v", lastError)
}

// Collect all files from remote server
func collectRemoteFiles(serverURL string, metadata *Metadata) ([]FileInfo, int64, error) {
	var files []FileInfo
	var totalSize int64

	for _, fileInfo := range metadata.Files {
		fileURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(serverURL, "/"), fileInfo.Path)
		
		resp, err := http.Get(fileURL)
		if err != nil {
			fmt.Printf("Warning: Could not fetch %s: %v\n", fileInfo.Path, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Warning: File %s returned status %d\n", fileInfo.Path, resp.StatusCode)
			continue
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read %s: %v", fileInfo.Path, err)
		}

		hash := calculateRIPEMD160(content)
		
		size := resp.ContentLength
		if size == -1 {
			size = int64(len(content))
		}

		var modified time.Time
		lastModified := resp.Header.Get("Last-Modified")
		if lastModified != "" {
			if t, err := time.Parse(time.RFC1123, lastModified); err == nil {
				modified = t.UTC()
			} else if t, err := time.Parse(time.RFC1123Z, lastModified); err == nil {
				modified = t.UTC()
			} else {
				modified = time.Now().UTC()
			}
		} else {
			modified = time.Now().UTC()
		}

		file := FileInfo{
			Path:        fileInfo.Path,
			Hash:        hash,
			Size:        size,
			Modified:    modified,
			Permissions: "-rw-r--r--",
		}

		files = append(files, file)
		totalSize += size
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	return files, totalSize, nil
}

// Build a Merkle tree from a list of hashes
func buildMerkleTree(fileHashes []string) string {
	if len(fileHashes) == 0 {
		return calculateRIPEMD160([]byte(""))
	}

	var nodes []string
	for _, hash := range fileHashes {
		nodes = append(nodes, hash)
	}

	if len(nodes)%2 == 1 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	for len(nodes) > 1 {
		var newLevel []string

		for i := 0; i < len(nodes); i += 2 {
			var combined string
			if i+1 < len(nodes) {
				combined = nodes[i] + nodes[i+1]
			} else {
				combined = nodes[i] + nodes[i]
			}
			newLevel = append(newLevel, calculateRIPEMD160([]byte(combined)))
		}

		if len(newLevel)%2 == 1 && len(newLevel) > 1 {
			newLevel = append(newLevel, newLevel[len(newLevel)-1])
		}

		nodes = newLevel
	}

	if len(nodes) == 0 {
		return calculateRIPEMD160([]byte(""))
	}
	return nodes[0]
}

// Compare two sets of files and detect changes
func compareFiles(original, current []FileInfo) *ChangeResult {
	result := &ChangeResult{
		Added:     []FileInfo{},
		Modified:  []FileInfo{},
		Deleted:   []FileInfo{},
		Unchanged: []FileInfo{},
	}

	originalMap := make(map[string]FileInfo)
	currentMap := make(map[string]FileInfo)

	for _, file := range original {
		originalMap[file.Path] = file
	}
	for _, file := range current {
		currentMap[file.Path] = file
	}

	for path, currentFile := range currentMap {
		originalFile, exists := originalMap[path]
		if !exists {
			result.Added = append(result.Added, currentFile)
		} else {
			if originalFile.Hash != currentFile.Hash {
				result.Modified = append(result.Modified, currentFile)
			} else {
				result.Unchanged = append(result.Unchanged, currentFile)
			}
		}
	}

	for path, originalFile := range originalMap {
		if _, exists := currentMap[path]; !exists {
			result.Deleted = append(result.Deleted, originalFile)
		}
	}

	sort.Slice(result.Added, func(i, j int) bool {
		return result.Added[i].Path < result.Added[j].Path
	})
	sort.Slice(result.Modified, func(i, j int) bool {
		return result.Modified[i].Path < result.Modified[j].Path
	})
	sort.Slice(result.Deleted, func(i, j int) bool {
		return result.Deleted[i].Path < result.Deleted[j].Path
	})

	return result
}

// Query DNS for Merkle hash
func queryDNSHash(domain string) (*DNSRecord, error) {
	attempts := []string{
		domain,
		"_merkle." + domain,
		"merkle." + domain,
		"integrity." + domain,
		"_integrity." + domain,
	}

	for _, d := range attempts {
		txtRecords, err := net.LookupTXT(d)
		if err != nil {
			continue
		}

		for _, record := range txtRecords {
			cleanRecord := strings.Trim(record, "\"")
			
			if strings.HasPrefix(cleanRecord, "{") {
				var dnsData map[string]interface{}
				if err := json.Unmarshal([]byte(cleanRecord), &dnsData); err == nil {
					hash, hashOK := dnsData["hash"].(string)
					excluded, excludedOK := dnsData["excluded_paths"].([]interface{})
					
					if hashOK && isHex(hash) && len(hash) == 40 {
						dnsRecord := &DNSRecord{
							Hash:      hash,
							Timestamp: time.Now().UTC(),
							Source:    "dns_json",
							Valid:     true,
						}
						
						if excludedOK {
							var excludedPaths []string
							for _, path := range excluded {
								if str, ok := path.(string); ok {
									excludedPaths = append(excludedPaths, str)
								}
							}
							dnsRecord.ExcludedPaths = excludedPaths
							dnsRecord.ExcludedCount = len(excludedPaths)
						}
						
						return dnsRecord, nil
					}
				}
			}

			if strings.HasPrefix(cleanRecord, "merkle-root=") {
				hash := strings.TrimPrefix(cleanRecord, "merkle-root=")
				if isHex(hash) && len(hash) == 40 {
					return &DNSRecord{
						Hash:      hash,
						Timestamp: time.Now().UTC(),
						Source:    "dns",
						Valid:     true,
					}, nil
				}
			}

			if strings.HasPrefix(cleanRecord, "merkle-hash=") {
				hash := strings.TrimPrefix(cleanRecord, "merkle-hash=")
				if isHex(hash) && len(hash) == 40 {
					return &DNSRecord{
						Hash:      hash,
						Timestamp: time.Now().UTC(),
						Source:    "dns",
						Valid:     true,
					}, nil
				}
			}

			// Reiner Hash
			if len(cleanRecord) == 40 && isHex(cleanRecord) {
				return &DNSRecord{
					Hash:      cleanRecord,
					Timestamp: time.Now().UTC(),
					Source:    "dns",
					Valid:     true,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid merkle hash found in DNS TXT records")
}

// Extract domain from URL
func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// Format time to UTC with Unix timestamp
func formatTimeUTC(t time.Time) string {
	utcTime := t.UTC()
	return fmt.Sprintf("%s (Unix: %d)", 
		utcTime.Format("2006-01-02 15:04:05 MST"), 
		utcTime.Unix())
}

// Format bytes to human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func displayResults(result *VerificationResult) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("REMOTE MERKLE TREE VERIFICATION RESULT")
	fmt.Println(strings.Repeat("=", 70))

	fmt.Printf("Server URL:       %s\n", result.ServerURL)
	fmt.Printf("Verification Date: %s\n", formatTimeUTC(result.VerificationDate))
	fmt.Printf("Domain:           %s\n", result.Domain)
	
	if result.OriginalMetadata != nil && len(result.OriginalMetadata.ExcludedPaths) > 0 {
		fmt.Printf("Excluded Files:   %d (e.g., .well-known/, .git/)\n", 
			len(result.OriginalMetadata.ExcludedPaths))
	}
	fmt.Println()

	if !result.Success {
		fmt.Printf("VERIFICATION FAILED: %s\n", result.ErrorMessage)
		return
	}

	fmt.Printf("STATUS: %s\n", result.Changes.Message)
	if result.ExcludedInfo != "" {
		fmt.Printf("NOTE: %s\n", result.ExcludedInfo)
	}
	fmt.Println()

	fmt.Println("COMPARISON RESULTS:")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("  Original Root Hash:    %s\n", result.OriginalMetadata.RootHash)
	fmt.Printf("  Calculated Root Hash:  %s\n", result.CalculatedRoot)
	fmt.Printf("  Root Hash Match:       %v\n", result.RootMatch)
	fmt.Printf("  Metadata Created:      %s\n", formatTimeUTC(result.OriginalMetadata.CreatedAt))
	fmt.Printf("  Original File Count:   %d (included)\n", len(result.OriginalMetadata.Files))
	fmt.Printf("  Current File Count:    %d (included)\n", len(result.CurrentFiles))
	
	if len(result.OriginalMetadata.ExcludedPaths) > 0 {
		fmt.Printf("  Excluded Paths:        %d (not verified)\n", 
			len(result.OriginalMetadata.ExcludedPaths))
		if len(result.OriginalMetadata.ExcludedPaths) <= 5 {
			for _, path := range result.OriginalMetadata.ExcludedPaths {
				fmt.Printf("    - %s\n", path)
			}
		} else {
			fmt.Printf("    (e.g., %s, ...)\n", 
				strings.Join(result.OriginalMetadata.ExcludedPaths[:min(3, len(result.OriginalMetadata.ExcludedPaths))], ", "))
		}
	}
	
	fmt.Printf("  Original Total Size:   %s (included files)\n", 
		formatBytes(result.OriginalMetadata.TotalSize))
	fmt.Printf("  Current Total Size:    %s (included files)\n", 
		formatBytes(getTotalSize(result.CurrentFiles)))
	fmt.Println()

	if result.DNSRecord != nil {
		fmt.Println("DNS VERIFICATION:")
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("  DNS Hash:             %s\n", result.DNSRecord.Hash)
		fmt.Printf("  DNS Source:           %s\n", result.DNSRecord.Source)
		fmt.Printf("  DNS Query Time:       %s\n", formatTimeUTC(result.DNSRecord.Timestamp))
		fmt.Printf("  DNS Hash Valid:       %v\n", result.DNSRecord.Valid)
		if result.DNSRecord.ExcludedCount > 0 {
			fmt.Printf("  DNS Excluded Count:   %d files\n", result.DNSRecord.ExcludedCount)
		}
		fmt.Printf("  DNS Hash Match:       %v\n", result.DNSMatch)
		if !result.DNSMatch {
			fmt.Printf("  WARNING: DNS hash does not match calculated hash!\n")
		}
		fmt.Println()
	}

	if len(result.Changes.Added) > 0 {
		fmt.Printf("ADDED FILES (%d):\n", len(result.Changes.Added))
		fmt.Println(strings.Repeat("-", 20))
		for _, file := range result.Changes.Added {
			fmt.Printf("  File: %s\n", file.Path)
			fmt.Printf("    Size:     %s\n", formatBytes(file.Size))
			fmt.Printf("    Modified: %s\n", formatTimeUTC(file.Modified))
			fmt.Printf("    Hash:     %s\n", file.Hash)
		}
		fmt.Println()
	}

	if len(result.Changes.Modified) > 0 {
		fmt.Printf("MODIFIED FILES (%d):\n", len(result.Changes.Modified))
		fmt.Println(strings.Repeat("-", 25))
		for _, file := range result.Changes.Modified {
			var originalFile *FileInfo
			for _, f := range result.OriginalMetadata.Files {
				if f.Path == file.Path {
					originalFile = &f
					break
				}
			}
			
			if originalFile != nil {
				fmt.Printf("  File: %s\n", file.Path)
				fmt.Printf("    Original Hash: %s\n", originalFile.Hash)
				fmt.Printf("    Current Hash:  %s\n", file.Hash)
				fmt.Printf("    Original Size: %s\n", formatBytes(originalFile.Size))
				fmt.Printf("    Current Size:  %s\n", formatBytes(file.Size))
				fmt.Printf("    Original Modified: %s\n", formatTimeUTC(originalFile.Modified))
				fmt.Printf("    Current Modified:  %s\n", formatTimeUTC(file.Modified))
			}
		}
		fmt.Println()
	}

	if len(result.Changes.Deleted) > 0 {
		fmt.Printf("DELETED FILES (%d):\n", len(result.Changes.Deleted))
		fmt.Println(strings.Repeat("-", 25))
		for _, file := range result.Changes.Deleted {
			fmt.Printf("  File: %s\n", file.Path)
			fmt.Printf("    Last Size:     %s\n", formatBytes(file.Size))
			fmt.Printf("    Last Modified: %s\n", formatTimeUTC(file.Modified))
			fmt.Printf("    Last Hash:     %s\n", file.Hash)
		}
		fmt.Println()
	}

	if len(result.Changes.Unchanged) > 0 {
		fmt.Printf("UNCHANGED FILES: %d files (included)\n", len(result.Changes.Unchanged))
		if len(result.Changes.Unchanged) <= 10 {
			for _, file := range result.Changes.Unchanged {
				fmt.Printf("  - %s\n", file.Path)
			}
		} else {
			fmt.Printf("  (First 10 files: ")
			for i := 0; i < 10 && i < len(result.Changes.Unchanged); i++ {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s", result.Changes.Unchanged[i].Path)
			}
			if len(result.Changes.Unchanged) > 10 {
				fmt.Printf(", ...")
			}
			fmt.Printf(")\n")
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}

// Helper to calculate total size of files
func getTotalSize(files []FileInfo) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

// Main verification function
func verifyRemote(serverURL string, useDNS bool) *VerificationResult {
	result := &VerificationResult{
		ServerURL:        serverURL,
		Domain:           extractDomain(serverURL),
		VerificationDate: time.Now().UTC(),
		Success:          false,
	}

	fmt.Printf("Starting remote verification of: %s\n", serverURL)
	if useDNS {
		fmt.Printf("Domain for DNS lookup: %s\n", result.Domain)
	}
	fmt.Println(strings.Repeat("-", 70))

	// Try DNS lookup if requested
	if useDNS {
		fmt.Println("Querying DNS for Merkle hash...")
		dnsRecord, err := queryDNSHash(result.Domain)
		if err != nil {
			fmt.Printf("DNS query failed: %v\n", err)
		} else {
			result.DNSRecord = dnsRecord
			fmt.Printf("DNS hash found: %s\n", dnsRecord.Hash)
			if dnsRecord.ExcludedCount > 0 {
				fmt.Printf("DNS reports %d excluded files\n", dnsRecord.ExcludedCount)
			}
		}
	}

	// Fetch metadata from server
	fmt.Println("\nFetching metadata from server...")
	metadata, err := fetchMetadata(serverURL)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to fetch metadata: %v", err)
		return result
	}
	result.OriginalMetadata = metadata

	fmt.Printf("Metadata found. Created: %s\n", formatTimeUTC(metadata.CreatedAt))
	fmt.Printf("Original file count: %d (included)\n", metadata.FileCount)
	
	if len(metadata.ExcludedPaths) > 0 {
		fmt.Printf("Excluded files: %d (e.g., %s)\n", 
			len(metadata.ExcludedPaths),
			strings.Join(metadata.ExcludedPaths[:min(3, len(metadata.ExcludedPaths))], ", "))
		result.ExcludedInfo = fmt.Sprintf("%d files were excluded from verification (.well-known/, .git/, etc.)", 
			len(metadata.ExcludedPaths))
	}

	// Collect current files
	fmt.Println("\nCollecting current files from server...")
	currentFiles, _, err := collectRemoteFiles(serverURL, metadata)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to collect files: %v", err)
		return result
	}
	result.CurrentFiles = currentFiles

	// Calculate current hashes and Merkle root
	fmt.Println("Calculating hashes and Merkle root...")
	var currentHashes []string
	for _, file := range currentFiles {
		currentHashes = append(currentHashes, file.Hash)
	}
	result.CalculatedRoot = buildMerkleTree(currentHashes)

	// Compare root hashes
	result.RootMatch = metadata.RootHash == result.CalculatedRoot

	// Compare individual files
	result.Changes = compareFiles(metadata.Files, currentFiles)

	// Set result message
	if result.RootMatch && len(result.Changes.Added) == 0 && 
	   len(result.Changes.Modified) == 0 && len(result.Changes.Deleted) == 0 {
		result.Changes.Message = "Folder is UNCHANGED. All included files are identical."
	} else {
		result.Changes.Message = "Folder has been MODIFIED."
	}

	// Compare with DNS if available
	if result.DNSRecord != nil {
		result.DNSMatch = result.DNSRecord.Hash == result.CalculatedRoot
	}

	result.Success = true
	return result
}

// Save verification result to JSON file
func saveVerificationResult(result *VerificationResult) error {
	timestamp := result.VerificationDate.Format("20060102_150405")
	filename := fmt.Sprintf("verification_%s_%s.json", 
		strings.ReplaceAll(result.Domain, ".", "_"), 
		timestamp)

	reportJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %v", err)
	}

	if err := os.WriteFile(filename, reportJSON, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	fmt.Printf("\nDetailed verification report saved to: %s\n", filename)
	return nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Remote Merkle Tree Integrity Verifier")
		fmt.Println("Version:", Version)
		fmt.Println("Algorithm:", Algorithm)
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  mfvc <server-url> [--dns] [--save] [--download]")
		fmt.Println()
		fmt.Println("Arguments:")
		fmt.Println("  <server-url>    URL of the server to verify")
		fmt.Println("  --dns           Also verify against DNS TXT records")
		fmt.Println("  --save          Save detailed JSON report")
		fmt.Println("  --download      Download proof files (.well-known/mfv/*)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mfvc https://example.com")
		fmt.Println("  mfvc https://example.com --dns")
		fmt.Println("  mfvc https://example.com --dns --save")
		fmt.Println("  mfvc https://example.com --download")
		fmt.Println("  mfvc http://192.168.1.100:8080 --download")
		os.Exit(1)
	}

	serverURL := os.Args[1]
	useDNS := false
	saveReport := false
	downloadProofsFlag := false

	for _, arg := range os.Args[2:] {
		switch arg {
		case "--dns":
			useDNS = true
		case "--save":
			saveReport = true
		case "--download":
			downloadProofsFlag = true
		default:
			fmt.Printf("Warning: Unknown argument: %s\n", arg)
		}
	}

	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}

	// Handle download mode
	if downloadProofsFlag {
		downloadProofs(serverURL)
		// Even in download mode, we can still do verification
		if useDNS || saveReport {
			fmt.Println("\n" + strings.Repeat("=", 70))
			fmt.Println("CONTINUING WITH VERIFICATION AFTER DOWNLOAD")
			fmt.Println(strings.Repeat("=", 70))
			result := verifyRemote(serverURL, useDNS)
			displayResults(result)

			if saveReport && result.Success {
				if err := saveVerificationResult(result); err != nil {
					fmt.Printf("Warning: Could not save report: %v\n", err)
				}
			}

			if !result.Success {
				os.Exit(1)
			}
		}
		return
	}

	// Normal verification mode
	result := verifyRemote(serverURL, useDNS)
	displayResults(result)

	if saveReport && result.Success {
		if err := saveVerificationResult(result); err != nil {
			fmt.Printf("Warning: Could not save report: %v\n", err)
		}
	}

	if !result.Success {
		os.Exit(1)
	}
}
