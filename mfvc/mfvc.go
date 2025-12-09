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
	Domain        string     `json:"domain,omitempty"`
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
	URLDomain        string        `json:"url_domain"`
	MetadataDomain   string        `json:"metadata_domain"`
	VerificationDate time.Time     `json:"verification_date"`
	OriginalMetadata *Metadata     `json:"original_metadata"`
	CurrentFiles     []FileInfo    `json:"current_files"`
	Changes          *ChangeResult `json:"changes"`
	CalculatedRoot   string        `json:"calculated_root"`
	CalculatedHash   string        `json:"calculated_hash"`
	DNSRecord        *DNSRecord    `json:"dns_record,omitempty"`
	DNSMatch         bool          `json:"dns_match,omitempty"`
	RootMatch        bool          `json:"root_match"`
	Success          bool          `json:"success"`
	ErrorMessage     string        `json:"error_message,omitempty"`
	ExcludedInfo     string        `json:"excluded_info,omitempty"`
	SecurityWarning  string        `json:"security_warning,omitempty"`
	ContentTheft     bool          `json:"content_theft"`
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
	Version   = "0.4.0"
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

// Apply domain binding to root hash
func applyDomainBinding(rootHash string, domain string) string {
	if domain == "" {
		return rootHash
	}
	combined := domain + rootHash
	return calculateRIPEMD160([]byte(combined))
}

// Download file from URL and save to local path
func downloadFile(url string, filepath string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filepath, err)
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s for %s", resp.Status, url)
	}

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
	fmt.Println("Mode: Download only - verification may fail")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Server URL: %s\n", serverURL)
	fmt.Println()

	filesToDownload := []struct {
		remotePath string
		localName  string
		optional   bool
	}{
		{".well-known/mfv/merkle_metadata.json", "merkle_metadata.json", false},
		{".well-known/mfv/merkle_metadata.json.ots", "merkle_metadata.json.ots", true},
		{".well-known/mfv/dns.txt", "dns.txt", true},
		{".well-known/mfv/dns.txt.ots", "dns.txt.ots", true},
		{".well-known/merkle-metadata.json", "merkle_metadata.json", false},
		{".well-known/merkle-metadata.json.ots", "merkle_metadata.json.ots", true},
		{".well-known/dns.txt", "dns.txt", true},
		{".well-known/dns.txt.ots", "dns.txt.ots", true},
	}

	successCount := 0
	var totalSize int64

	for _, file := range filesToDownload {
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
		
		fmt.Printf("Trying: %s ... ", url)

		if err := downloadFile(url, file.localName); err == nil {
			if info, err := os.Stat(file.localName); err == nil {
				totalSize += info.Size()
			}

			result.Files = append(result.Files, file.localName)
			successCount++
			fmt.Printf("✓\n")
		} else {
			if file.optional {
				fmt.Printf("✗ (optional)\n")
			} else {
				fmt.Printf("✗\n")
				result.ErrorMessages = append(result.ErrorMessages, 
					fmt.Sprintf("Failed to download %s: %v", file.remotePath, err))
			}
		}
	}

	result.TotalSize = totalSize
	
	// Success if we got at least the metadata file
	for _, file := range result.Files {
		if file == "merkle_metadata.json" {
			result.Success = true
			break
		}
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Download Summary:\n")
	fmt.Printf("  Files downloaded: %d\n", successCount)
	fmt.Printf("  Total size: %s\n", formatBytes(totalSize))
	
	if len(result.Files) > 0 {
		fmt.Printf("  Downloaded files:\n")
		for _, file := range result.Files {
			fmt.Printf("    • %s\n", file)
		}
	}
	
	if len(result.ErrorMessages) > 0 {
		fmt.Printf("  Errors:\n")
		for _, err := range result.ErrorMessages {
			fmt.Printf("    • %s\n", err)
		}
	}
	
	if !result.Success {
		fmt.Printf("      Warning: Could not download merkle_metadata.json\n")
		fmt.Printf("     The server may not have proof files configured.\n")
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

			// Plain hash
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
	return fmt.Sprintf("%s (Unix ET: %d)", 
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

// Display verification results
func displayResults(result *VerificationResult) {
	fmt.Println(strings.Repeat("=", 70))
	
	if result.ContentTheft {
		fmt.Println("   CONTENT THEFT DETECTED - VERIFICATION FAILED   ")
	} else if !result.Success {
		fmt.Println("   VERIFICATION FAILED   ")
	} else {
		fmt.Println("   VERIFICATION SUCCESSFUL   ")
	}
	
	fmt.Println(strings.Repeat("=", 70))

	fmt.Printf("Server URL:       %s\n", result.ServerURL)
	fmt.Printf("Verification Date: %s\n", formatTimeUTC(result.VerificationDate))
	fmt.Printf("URL Domain:       %s\n", result.URLDomain)
	if result.MetadataDomain != "" {
		fmt.Printf("Metadata Domain:  %s\n", result.MetadataDomain)
	}
	
	if result.OriginalMetadata != nil && len(result.OriginalMetadata.ExcludedPaths) > 0 {
		fmt.Printf("Excluded Files:   %d\n", len(result.OriginalMetadata.ExcludedPaths))
	}
	fmt.Println()

	if result.ContentTheft {
		fmt.Println(strings.Repeat("!", 70))
		fmt.Println("SECURITY VIOLATION: CONTENT THEFT DETECTED")
		fmt.Println(strings.Repeat("!", 70))
		fmt.Println("The hash verification would succeed, but this indicates that")
		fmt.Println("the content has been copied to a different domain.")
		fmt.Println()
		fmt.Println("DOMAIN BINDING SECURITY PRINCIPLE:")
		fmt.Println("• Each domain must have its own unique hash")
		fmt.Println("• Identical content on different domains = CONTENT THEFT")
		fmt.Println("• No domain migration is allowed in this security model")
		fmt.Println(strings.Repeat("!", 70))
		fmt.Println()
	}

	if !result.Success && result.ErrorMessage != "" {
		fmt.Printf("ERROR: %s\n", result.ErrorMessage)
		return
	}

	fmt.Printf("STATUS: %s\n", result.Changes.Message)
	if result.SecurityWarning != "" {
		fmt.Printf("SECURITY WARNING: %s\n", result.SecurityWarning)
	}
	if result.ExcludedInfo != "" {
		fmt.Printf("NOTE: %s\n", result.ExcludedInfo)
	}
	fmt.Println()

	fmt.Println("DOMAIN VERIFICATION (STRICT MODE):")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("  URL Domain:             %s\n", result.URLDomain)
	if result.MetadataDomain != "" {
		fmt.Printf("  Metadata Domain:        %s\n", result.MetadataDomain)
		
		// STRICT CHECK: Domains MUST match
		if result.URLDomain != result.MetadataDomain {
			fmt.Printf("      DOMAIN MISMATCH:     %s != %s\n", 
				result.URLDomain, result.MetadataDomain)
			fmt.Printf("     SECURITY VIOLATION: Domain binding mismatch\n")
		} else {
			fmt.Printf("     Domain Match:        Perfect\n")
		}
	} else {
		fmt.Printf("  Metadata Domain:        (not specified - legacy)\n")
		fmt.Printf("      WARNING:             No domain binding in metadata\n")
	}
	fmt.Println()

	fmt.Println("HASH VERIFICATION:")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("  Original Root Hash:     %s\n", result.OriginalMetadata.RootHash)
	fmt.Printf("  Calculated Merkle Root: %s\n", result.CalculatedRoot)
	fmt.Printf("  Calculated Final Hash:  %s (with domain: %s)\n", 
		result.CalculatedHash, result.URLDomain)
	
	if result.MetadataDomain != "" && result.MetadataDomain != result.URLDomain {
		hashWithMeta := applyDomainBinding(result.CalculatedRoot, result.MetadataDomain)
		fmt.Printf("  Hash with Meta Domain: %s (for comparison)\n", hashWithMeta)
		
		if result.OriginalMetadata.RootHash == hashWithMeta {
			fmt.Printf("      WARNING: Hash matches metadata domain '%s'\n", 
				result.MetadataDomain)
			fmt.Printf("     This indicates the content was copied from '%s'\n", 
				result.MetadataDomain)
			result.ContentTheft = true
		}
	}
	
	fmt.Printf("  Root Hash Match:        %v\n", result.RootMatch)
	
	if !result.RootMatch && result.MetadataDomain != "" && result.URLDomain != result.MetadataDomain {
		fmt.Printf("      Expected behavior: Hash should not match across domains\n")
		fmt.Printf("     Domain binding is working correctly to prevent copying\n")
	}
	
	fmt.Printf("  Metadata Created:       %s\n", formatTimeUTC(result.OriginalMetadata.CreatedAt))
	fmt.Printf("  Original File Count:    %d (included)\n", len(result.OriginalMetadata.Files))
	fmt.Printf("  Current File Count:     %d (included)\n", len(result.CurrentFiles))
	
	if len(result.OriginalMetadata.ExcludedPaths) > 0 {
		fmt.Printf("  Excluded Paths:         %d (not verified)\n", 
			len(result.OriginalMetadata.ExcludedPaths))
	}
	
	fmt.Printf("  Original Total Size:    %s\n", 
		formatBytes(result.OriginalMetadata.TotalSize))
	fmt.Printf("  Current Total Size:     %s\n", 
		formatBytes(getTotalSize(result.CurrentFiles)))
	fmt.Println()

	if result.DNSRecord != nil {
		fmt.Println("DNS VERIFICATION:")
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("  DNS Hash:              %s\n", result.DNSRecord.Hash)
		fmt.Printf("  DNS Source:            %s\n", result.DNSRecord.Source)
		fmt.Printf("  DNS Query Time:        %s\n", formatTimeUTC(result.DNSRecord.Timestamp))
		fmt.Printf("  DNS Hash Valid:        %v\n", result.DNSRecord.Valid)
		if result.DNSRecord.ExcludedCount > 0 {
			fmt.Printf("  DNS Excluded Count:    %d files\n", result.DNSRecord.ExcludedCount)
		}
		fmt.Printf("  DNS Hash Match:        %v\n", result.DNSMatch)
		if !result.DNSMatch {
			fmt.Printf("      DNS WARNING: Hash does not match!\n")
		}
		fmt.Println()
	}

	if len(result.Changes.Added) > 0 {
		fmt.Printf("ADDED FILES (%d):\n", len(result.Changes.Added))
		fmt.Println(strings.Repeat("-", 20))
		for _, file := range result.Changes.Added {
			fmt.Printf("  File: %s\n", file.Path)
		}
		fmt.Println()
	}

	if len(result.Changes.Modified) > 0 {
		fmt.Printf("MODIFIED FILES (%d):\n", len(result.Changes.Modified))
		fmt.Println(strings.Repeat("-", 25))
		for _, file := range result.Changes.Modified {
			fmt.Printf("  File: %s\n", file.Path)
		}
		fmt.Println()
	}

	if len(result.Changes.Deleted) > 0 {
		fmt.Printf("DELETED FILES (%d):\n", len(result.Changes.Deleted))
		fmt.Println(strings.Repeat("-", 25))
		for _, file := range result.Changes.Deleted {
			fmt.Printf("  File: %s\n", file.Path)
		}
		fmt.Println()
	}

	if len(result.Changes.Unchanged) > 0 {
		fmt.Printf("UNCHANGED FILES: %d files\n", len(result.Changes.Unchanged))
	}

	fmt.Println(strings.Repeat("=", 70))
	if result.ContentTheft {
		fmt.Println("   FINAL VERDICT: CONTENT THEFT - VERIFICATION REJECTED   ")
		fmt.Println("   The website appears to be a copy of another domain.")
		fmt.Println("   This violates the domain binding security principle.")
	} else if result.Success && result.RootMatch {
		fmt.Println("   FINAL VERDICT: VERIFICATION SUCCESSFUL   ")
		fmt.Println("   All files are intact and domain binding is correct.")
	} else if result.Success && !result.RootMatch {
		fmt.Println("    FINAL VERDICT: CONTENT MODIFIED   ")
		fmt.Println("   Some files have been added, modified, or deleted.")
	} else {
		fmt.Println("   FINAL VERDICT: VERIFICATION FAILED   ")
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

// Main verification function - STRICT MODE, NO MIGRATION
func verifyRemote(serverURL string, useDNS bool) *VerificationResult {
	urlDomain := extractDomain(serverURL)
	
	result := &VerificationResult{
		ServerURL:        serverURL,
		URLDomain:        urlDomain,
		VerificationDate: time.Now().UTC(),
		Success:          false,
		ContentTheft:     false,
	}

	fmt.Printf("Starting STRICT verification of: %s\n", serverURL)
	fmt.Printf("URL Domain: %s\n", urlDomain)
	fmt.Println("STRICT MODE: No domain migration allowed")
	fmt.Println(strings.Repeat("-", 70))

	if useDNS {
		fmt.Println("Querying DNS for Merkle hash...")
		dnsRecord, err := queryDNSHash(urlDomain)
		if err != nil {
			fmt.Printf("DNS query failed: %v\n", err)
		} else {
			result.DNSRecord = dnsRecord
			fmt.Printf("DNS hash found: %s\n", dnsRecord.Hash)
		}
	}

	fmt.Println("\nFetching metadata from server...")
	metadata, err := fetchMetadata(serverURL)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to fetch metadata: %v", err)
		return result
	}
	result.OriginalMetadata = metadata
	result.MetadataDomain = metadata.Domain

	fmt.Printf("Metadata found. Created: %s\n", formatTimeUTC(metadata.CreatedAt))
	fmt.Printf("Original file count: %d (included)\n", metadata.FileCount)
	
	if metadata.Domain != "" {
		fmt.Printf("Metadata domain: %s\n", metadata.Domain)
		
		if urlDomain != metadata.Domain {
			result.SecurityWarning = fmt.Sprintf(
				"DOMAIN MISMATCH: URL '%s' ≠ Metadata '%s'. " +
				"This indicates potential content theft.", 
				urlDomain, metadata.Domain)
			fmt.Printf("   SECURITY ALERT: %s\n", result.SecurityWarning)
		}
	} else {
		fmt.Printf("No domain specified in metadata (legacy/unsafe format)\n")
		result.SecurityWarning = "No domain binding in metadata - legacy format"
	}
	
	if len(metadata.ExcludedPaths) > 0 {
		fmt.Printf("Excluded files: %d\n", len(metadata.ExcludedPaths))
		result.ExcludedInfo = fmt.Sprintf("%d files excluded from verification", 
			len(metadata.ExcludedPaths))
	}

	fmt.Println("\nCollecting current files from server...")
	currentFiles, _, err := collectRemoteFiles(serverURL, metadata)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to collect files: %v", err)
		return result
	}
	result.CurrentFiles = currentFiles

	fmt.Println("Calculating hashes and Merkle root...")
	var currentHashes []string
	for _, file := range currentFiles {
		currentHashes = append(currentHashes, file.Hash)
	}
	
	merkleRoot := buildMerkleTree(currentHashes)
	result.CalculatedRoot = merkleRoot
	
	fmt.Println("\nPerforming STRICT hash verification...")
	
	calculatedHash := applyDomainBinding(merkleRoot, urlDomain)
	result.CalculatedHash = calculatedHash
	
	result.RootMatch = (metadata.RootHash == calculatedHash)
	
	// CONTENT THEFT DETECTION
	if metadata.Domain != "" && urlDomain != metadata.Domain {
		hashWithMetaDomain := applyDomainBinding(merkleRoot, metadata.Domain)
		
		if metadata.RootHash == hashWithMetaDomain {
			result.ContentTheft = true
			result.SecurityWarning = fmt.Sprintf(
				"CONTENT THEFT DETECTED: This site appears to be a copy of '%s'", 
				metadata.Domain)
			fmt.Printf("   CONTENT THEFT: Hash matches original domain '%s'\n", 
				metadata.Domain)
			fmt.Printf("   This violates domain binding security principle\n")
		}
	}

	result.Changes = compareFiles(metadata.Files, currentFiles)

	if result.RootMatch && len(result.Changes.Added) == 0 && 
	   len(result.Changes.Modified) == 0 && len(result.Changes.Deleted) == 0 {
		result.Changes.Message = "All files unchanged and domain binding correct."
	} else if result.ContentTheft {
		result.Changes.Message = "CONTENT THEFT DETECTED - Site appears to be a copy."
	} else {
		result.Changes.Message = "Files have been modified or domain mismatch detected."
	}

	if result.DNSRecord != nil {
		dnsMatches := result.DNSRecord.Hash == calculatedHash
		
		if metadata.Domain != "" && urlDomain != metadata.Domain {
			hashWithMeta := applyDomainBinding(merkleRoot, metadata.Domain)
			if result.DNSRecord.Hash == hashWithMeta {
				fmt.Printf("    DNS Warning: DNS hash matches original domain '%s'\n", 
					metadata.Domain)
			}
		}
		
		result.DNSMatch = dnsMatches
		
		if !dnsMatches {
			result.SecurityWarning = "DNS hash does not match calculated hash"
		}
	}

	// FINAL SUCCESS DETERMINATION
	if result.RootMatch && !result.ContentTheft {
		result.Success = true
	} else {
		result.Success = false
	}

	return result
}

// Save verification result to JSON file
func saveVerificationResult(result *VerificationResult) error {
	timestamp := result.VerificationDate.Format("20060102_150405")
	filename := fmt.Sprintf("verification_%s_%s.json", 
		strings.ReplaceAll(result.URLDomain, ".", "_"), 
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
		fmt.Println("Remote Merkle Tree Integrity Verifier - STRICT MODE")
		fmt.Println("Version:", Version)
		fmt.Println("Algorithm:", Algorithm)
		fmt.Println()
		fmt.Println("STRICT SECURITY POLICY:")
		fmt.Println("• Domain binding is MANDATORY")
		fmt.Println("• No domain migration allowed")
		fmt.Println("• Content copying between domains = THEFT")
		fmt.Println("• Verification fails on domain mismatch")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  mfvc <server-url> [--dns] [--save] [--download]")
		fmt.Println()
		fmt.Println("Arguments:")
		fmt.Println("  <server-url>    URL of the server to verify")
		fmt.Println("  --dns           Also verify against DNS TXT records")
		fmt.Println("  --save          Save detailed JSON report (even if failed)")
		fmt.Println("  --download      Download proof files (works even if verification fails)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mfvc https://example.com")
		fmt.Println("  mfvc https://example.com --dns")
		fmt.Println("  mfvc https://example.com --dns --save")
		fmt.Println("  mfvc https://example.com --download")
		fmt.Println("  mfvc https://suspicious-site.com --download  # Download proofs for analysis")
		os.Exit(1)
	}

	serverURL := os.Args[1]
	useDNS := false
	saveReport := false
	downloadProofsFlag := false

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--dns":
			useDNS = true
		case "--save":
			saveReport = true
		case "--download":
			downloadProofsFlag = true
		default:
			fmt.Printf("Warning: Unknown argument: %s\n", os.Args[i])
		}
	}

	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}

	// Handle download mode
	if downloadProofsFlag {
		downloadProofs(serverURL)
		
		// Only ask if ONLY --download was specified (no other verification params)
		if !useDNS && !saveReport {
			// Pure download mode - ask if user wants verification
			fmt.Print("\nDo you want to continue with verification? (y/n): ")
			var response string
			fmt.Scanln(&response)
			
			if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
				fmt.Println("\n" + strings.Repeat("=", 70))
				fmt.Println("CONTINUING WITH STRICT VERIFICATION AFTER DOWNLOAD")
				fmt.Println(strings.Repeat("=", 70))
				result := verifyRemote(serverURL, useDNS)
				displayResults(result)

				if saveReport {
					if err := saveVerificationResult(result); err != nil {
						fmt.Printf("Warning: Could not save report: %v\n", err)
					}
				}

				if !result.Success {
					fmt.Println("\nVerification failed, but proof files were downloaded.")
				}
			} else {
				fmt.Println("Download completed. Verification skipped.")
			}
		} else {
			// User specified --dns and/or --save with --download, so auto-continue
			fmt.Println("\n" + strings.Repeat("=", 70))
			fmt.Println("CONTINUING WITH VERIFICATION (--dns/--save specified)")
			fmt.Println(strings.Repeat("=", 70))
			result := verifyRemote(serverURL, useDNS)
			displayResults(result)

			if saveReport {
				if err := saveVerificationResult(result); err != nil {
					fmt.Printf("Warning: Could not save report: %v\n", err)
				}
			}

			if !result.Success {
				fmt.Println("\nVerification failed, but proof files were downloaded.")
			}
		}
		return
	}

	// Normal verification mode (without --download)
	result := verifyRemote(serverURL, useDNS)
	displayResults(result)

	if saveReport {
		if err := saveVerificationResult(result); err != nil {
			fmt.Printf("Warning: Could not save report: %v\n", err)
		}
	}

	if !result.Success {
		os.Exit(1)
	}
}
