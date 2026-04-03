package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ripemd160"
)

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  string
}

// MerkleTree represents the entire Merkle tree
type MerkleTree struct {
	Root       *MerkleNode
	FileCount  int
	CreatedAt  time.Time
	FolderPath string
}

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
	ExcludedPaths []string   `json:"excluded_paths"`
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

// Config for exclusions
type Config struct {
	ExcludePatterns []string `json:"exclude_patterns"`
	ExcludePaths    []string `json:"exclude_paths"`
}

// Default configuration - .well-known is excluded EXCEPT for yubicrypt
var defaultConfig = Config{
	ExcludePatterns: []string{
		".well-known/*",     // Exclude all .well-known by default
		"*.tmp",
		"*.log",
		".git/*",
		".DS_Store",
		"Thumbs.db",
		"merkle_metadata.json",
		"verification_report.json",
		"merkle_config.json",
	},
	ExcludePaths: []string{
		".well-known",       // Exclude .well-known directory
		".git",
	},
}

// Constants
const (
	Version      = "0.4.0"
	Algorithm    = "RIPEMD-160"
	MetadataFile = "merkle_metadata.json"
	ConfigFile   = "merkle_config.json"
	YubiCryptDir = ".well-known/yubicrypt" // YubiCrypt certificates directory - ONLY this is included
)

// Calculate RIPEMD-160 hash for byte array
func calculateRIPEMD160(data []byte) string {
	hasher := ripemd160.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Hash a file with RIPEMD-160
func hashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := ripemd160.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Get file permissions in string format
func getFilePermissions(mode os.FileMode) string {
	return mode.String()
}

// Check if a path should be excluded - with special handling for YubiCrypt
func shouldExclude(path string, relPath string, config Config) bool {
	// SPECIAL RULE: NEVER exclude YubiCrypt directory contents
	if strings.Contains(relPath, YubiCryptDir) {
		return false
	}

	for _, excludePath := range config.ExcludePaths {
		if relPath == excludePath || strings.HasPrefix(relPath, excludePath+"/") {
			return true
		}
	}

	for _, pattern := range config.ExcludePatterns {
		matched, _ := filepath.Match(pattern, filepath.Base(relPath))
		if matched {
			return true
		}

		matched, _ = filepath.Match(pattern, relPath)
		if matched {
			return true
		}
	}

	return false
}

// Load configuration from file or use defaults
func loadConfig(configFile string) (Config, error) {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		configJSON, _ := json.MarshalIndent(defaultConfig, "", "  ")
		os.WriteFile(configFile, configJSON, 0644)
		return defaultConfig, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return defaultConfig, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return defaultConfig, err
	}

	return config, nil
}

// collectYubiCryptFiles collects all .crt and .ots files from .well-known/yubicrypt directory
func collectYubiCryptFiles(rootPath string) ([]FileInfo, error) {
	var yubicryptFiles []FileInfo
	yubicryptPath := filepath.Join(rootPath, YubiCryptDir)

	// Check if YubiCrypt directory exists
	if _, err := os.Stat(yubicryptPath); os.IsNotExist(err) {
		return yubicryptFiles, nil
	}

	err := filepath.Walk(yubicryptPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		// Only include .crt and .ots files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".crt" && ext != ".ots" {
			return nil
		}

		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hashing %s: %v", path, err)
		}

		fileInfo := FileInfo{
			Path:        relPath,
			Hash:        hash,
			Size:        info.Size(),
			Modified:    info.ModTime().UTC(),
			Permissions: getFilePermissions(info.Mode()),
		}

		yubicryptFiles = append(yubicryptFiles, fileInfo)
		return nil
	})

	return yubicryptFiles, err
}

// Collect all files in a folder (recursively) with exclusions, including only YubiCrypt from .well-known
func collectFiles(rootPath string, config Config) ([]FileInfo, int64, []string, []FileInfo, error) {
	var files []FileInfo
	var totalSize int64
	var excludedPaths []string

	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}

		// Check exclusions - YubiCrypt directory is specially included
		if shouldExclude(path, relPath, config) {
			excludedPaths = append(excludedPaths, relPath)
			return nil
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hashing %s: %v", path, err)
		}

		fileInfo := FileInfo{
			Path:        relPath,
			Hash:        hash,
			Size:        info.Size(),
			Modified:    info.ModTime().UTC(),
			Permissions: getFilePermissions(info.Mode()),
		}

		files = append(files, fileInfo)
		totalSize += info.Size()

		return nil
	})

	// Collect YubiCrypt certificate files (these are already included from above walk)
	// But we also want to track them separately for display
	yubicryptFiles, err := collectYubiCryptFiles(absRoot)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	sort.Strings(excludedPaths)
	return files, totalSize, excludedPaths, yubicryptFiles, err
}

// Build a Merkle tree from a list of hashes - EXACT SAME AS CLIENT
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

// For backward compatibility
func NewMerkleTree(fileHashes []string) *MerkleTree {
	merkleRoot := buildMerkleTree(fileHashes)

	return &MerkleTree{
		Root: &MerkleNode{
			Hash: merkleRoot,
		},
	}
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

// Save metadata to JSON file
func saveMetadata(metadata *Metadata, outputFile string) error {
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputFile, metadataJSON, 0644)
}

// Load metadata from JSON file
func loadMetadata(inputFile string) (*Metadata, error) {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}

	var metadata Metadata
	err = json.Unmarshal(data, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
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

// Apply domain binding to root hash (same as client)
func applyDomainBinding(rootHash string, domain string) string {
	if domain == "" {
		return rootHash
	}
	combined := domain + rootHash
	return calculateRIPEMD160([]byte(combined))
}

// displayYubiCryptInfo shows YubiCrypt certificate information in the terminal
func displayYubiCryptInfo(yubicryptFiles []FileInfo) {
	if len(yubicryptFiles) == 0 {
		return
	}

	// Count .crt and .ots files
	crtCount := 0
	otsCount := 0
	var crtHashes []string
	var crtPaths []string

	for _, file := range yubicryptFiles {
		if strings.HasSuffix(file.Path, ".crt") {
			crtCount++
			crtHashes = append(crtHashes, file.Hash)
			crtPaths = append(crtPaths, file.Path)
		} else if strings.HasSuffix(file.Path, ".ots") {
			otsCount++
		}
	}

	// Only display if we have .crt files with corresponding .ots files
	if crtCount > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("=", 70))
		fmt.Printf("YUBICRYPT CERTIFICATE VERIFICATION\n")
		fmt.Printf("%s\n", strings.Repeat("=", 70))
		fmt.Printf("%d yubicrypt certificate(s) found with respective .ots file(s)\n", crtCount)
		fmt.Printf("\nRIPEMD-160 hashes:\n")
		for i, hash := range crtHashes {
			fmt.Printf("  %d. %s (%s)\n", i+1, hash, crtPaths[i])
		}
		fmt.Printf("%s\n", strings.Repeat("=", 70))
	}
}

// Main function for "hash" command
func hashFolder(folderPath string, outputFile string, config Config, domain string) error {
	absPath, err := filepath.Abs(folderPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	fmt.Printf("Analyzing folder: %s\n", absPath)
	if domain != "" {
		fmt.Printf("Domain binding: %s\n", domain)
	}
	fmt.Printf("Using configuration: %s\n", ConfigFile)
	fmt.Println("Collecting files and calculating hashes...")
	fmt.Println("Note: Only .well-known/yubicrypt/ is included from .well-known/")
	fmt.Println("      Other .well-known/ contents are excluded for security.")

	// Collect files including YubiCrypt certificates
	files, totalSize, excludedPaths, yubicryptFiles, err := collectFiles(absPath, config)
	if err != nil {
		return fmt.Errorf("failed to collect files: %v", err)
	}

	var hashes []string
	for _, file := range files {
		hashes = append(hashes, file.Hash)
	}

	// Build Merkle tree using EXACT SAME algorithm as client
	merkleRoot := buildMerkleTree(hashes)

	// Apply domain binding if provided
	finalRootHash := merkleRoot
	if domain != "" {
		finalRootHash = applyDomainBinding(merkleRoot, domain)
	}

	// DEBUG: Show intermediate values
	fmt.Printf("\nDEBUG INFORMATION:\n")
	fmt.Printf("  Number of files: %d\n", len(files))
	fmt.Printf("  Merkle Root (without domain): %s\n", merkleRoot)
	if domain != "" {
		fmt.Printf("  Domain binding applied: %s\n", domain)
		fmt.Printf("  Final Root Hash (with domain): %s\n", finalRootHash)
	}

	metadata := &Metadata{
		RootHash:      finalRootHash,
		Domain:        domain,
		FolderPath:    absPath,
		CreatedAt:     time.Now().UTC(),
		FileCount:     len(files),
		TotalSize:     totalSize,
		Files:         files,
		Algorithm:     Algorithm,
		Version:       Version,
		ExcludedPaths: excludedPaths,
	}

	err = saveMetadata(metadata, outputFile)
	if err != nil {
		return fmt.Errorf("failed to save metadata: %v", err)
	}

	fmt.Println("\nAnalysis complete!")
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Root Hash:       %s\n", finalRootHash)
	if domain != "" {
		fmt.Printf("  Domain:          %s (bound to root hash)\n", domain)
		fmt.Printf("  Merkle Root:     %s (without domain, for debugging)\n", merkleRoot)
	}
	fmt.Printf("  Total Files:     %d (included)\n", len(files))
	fmt.Printf("  Excluded Files:  %d\n", len(excludedPaths))
	fmt.Printf("  Total Size:      %s (included files)\n", formatBytes(totalSize))
	fmt.Printf("  Created At:      %s\n", formatTimeUTC(metadata.CreatedAt))
	fmt.Printf("  Algorithm:       %s\n", Algorithm)
	fmt.Printf("  Metadata saved:  %s\n", outputFile)

	// Display YubiCrypt certificate information
	displayYubiCryptInfo(yubicryptFiles)

	if len(excludedPaths) > 0 {
		fmt.Printf("\nExcluded Paths (showing first 50):\n")
		displayCount := len(excludedPaths)
		if displayCount > 50 {
			displayCount = 50
		}
		for i := 0; i < displayCount; i++ {
			fmt.Printf("  %s\n", excludedPaths[i])
		}
		if len(excludedPaths) > 50 {
			fmt.Printf("  ... and %d more excluded paths\n", len(excludedPaths)-50)
		}
	}

	if len(files) > 0 {
		fmt.Println("\nFile Hashes (in order used for Merkle tree, showing first 50):")
		displayCount := len(files)
		if displayCount > 50 {
			displayCount = 50
		}
		for i := 0; i < displayCount; i++ {
			fmt.Printf("  %3d. %s: %s\n", i+1, files[i].Path, files[i].Hash)
		}
		if len(files) > 50 {
			fmt.Printf("  ... and %d more files\n", len(files)-50)
		}
	}

	return nil
}

// Main function for "verify" command
func verifyFolder(folderPath string, metadataFile string, config Config, domain string) error {
	absPath, err := filepath.Abs(folderPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	fmt.Printf("Verifying folder: %s\n", absPath)
	fmt.Printf("Using configuration: %s\n", ConfigFile)

	originalMetadata, err := loadMetadata(metadataFile)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %v", err)
	}

	domainForVerification := domain
	if domainForVerification == "" && originalMetadata.Domain != "" {
		domainForVerification = originalMetadata.Domain
		fmt.Printf("Using stored domain for verification: %s\n", domainForVerification)
	}

	if absPath != originalMetadata.FolderPath {
		fmt.Printf("Warning: Folder path differs from original\n")
		fmt.Printf("  Original: %s\n", originalMetadata.FolderPath)
		fmt.Printf("  Current:  %s\n", absPath)
		fmt.Println()
	}

	fmt.Println("Analyzing current folder state...")
	currentFiles, currentTotalSize, currentExcludedPaths, _, err := collectFiles(absPath, config)
	if err != nil {
		return fmt.Errorf("failed to collect current files: %v", err)
	}

	var currentHashes []string
	for _, file := range currentFiles {
		currentHashes = append(currentHashes, file.Hash)
	}

	// Use EXACT SAME algorithm as client
	currentMerkleRoot := buildMerkleTree(currentHashes)

	currentRootHash := currentMerkleRoot
	if domainForVerification != "" {
		currentRootHash = applyDomainBinding(currentMerkleRoot, domainForVerification)
	}

	rootMatch := originalMetadata.RootHash == currentRootHash

	changes := compareFiles(originalMetadata.Files, currentFiles)

	if rootMatch && len(changes.Added) == 0 && len(changes.Modified) == 0 && len(changes.Deleted) == 0 {
		changes.Message = "Folder is UNCHANGED. All included files are identical."
		changes.RootMatch = true
	} else {
		changes.Message = "Folder has been MODIFIED."
		changes.RootMatch = false
	}

	fmt.Printf("\n%s\n", changes.Message)
	fmt.Printf("\nComparison Results:\n")
	fmt.Printf("  Original Root:    %s\n", originalMetadata.RootHash)
	fmt.Printf("  Current Root:     %s\n", currentRootHash)
	fmt.Printf("  Root Match:       %v\n", rootMatch)
	if originalMetadata.Domain != "" {
		fmt.Printf("  Stored Domain:    %s\n", originalMetadata.Domain)
	}
	if domainForVerification != "" {
		fmt.Printf("  Domain Binding:   %s\n", domainForVerification)
		fmt.Printf("  Merkle Root:      %s (without domain)\n", currentMerkleRoot)
	}
	fmt.Printf("  Original Created: %s\n", formatTimeUTC(originalMetadata.CreatedAt))
	fmt.Printf("  Verification At:  %s\n", formatTimeUTC(time.Now().UTC()))
	fmt.Printf("  Original Files:   %d (included)\n", len(originalMetadata.Files))
	fmt.Printf("  Current Files:    %d (included)\n", len(currentFiles))
	fmt.Printf("  Original Excluded: %d files\n", len(originalMetadata.ExcludedPaths))
	fmt.Printf("  Current Excluded:  %d files\n", len(currentExcludedPaths))
	fmt.Printf("  Original Size:    %s (included)\n", formatBytes(originalMetadata.TotalSize))
	fmt.Printf("  Current Size:     %s (included)\n", formatBytes(currentTotalSize))

	if len(currentExcludedPaths) > 0 {
		fmt.Printf("\nCurrently Excluded Paths (showing first 50):\n")
		displayCount := len(currentExcludedPaths)
		if displayCount > 50 {
			displayCount = 50
		}
		for i := 0; i < displayCount; i++ {
			fmt.Printf("  %s\n", currentExcludedPaths[i])
		}
		if len(currentExcludedPaths) > 50 {
			fmt.Printf("  ... and %d more excluded paths\n", len(currentExcludedPaths)-50)
		}
	}

	if len(changes.Added) > 0 {
		fmt.Printf("\nAdded Files (%d):\n", len(changes.Added))
		for _, file := range changes.Added {
			fmt.Printf("  File: %s (Size: %s, Modified: %s)\n",
				file.Path,
				formatBytes(file.Size),
				formatTimeUTC(file.Modified))
		}
	}

	if len(changes.Modified) > 0 {
		fmt.Printf("\nModified Files (%d):\n", len(changes.Modified))
		for _, file := range changes.Modified {
			var originalFile *FileInfo
			for _, f := range originalMetadata.Files {
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
				fmt.Printf("    Original Modified:  %s\n", formatTimeUTC(originalFile.Modified))
				fmt.Printf("    Current Modified:   %s\n", formatTimeUTC(file.Modified))
			}
		}
	}

	if len(changes.Deleted) > 0 {
		fmt.Printf("\nDeleted Files (%d):\n", len(changes.Deleted))
		for _, file := range changes.Deleted {
			fmt.Printf("  File: %s (Size: %s, Last Modified: %s)\n",
				file.Path,
				formatBytes(file.Size),
				formatTimeUTC(file.Modified))
		}
	}

	if len(changes.Unchanged) > 0 && (len(changes.Added)+len(changes.Modified)+len(changes.Deleted) > 0) {
		fmt.Printf("\nUnchanged Files: %d files\n", len(changes.Unchanged))
	}

	report := map[string]interface{}{
		"verification_date":   time.Now().UTC().Format(time.RFC3339),
		"verification_unix":   time.Now().UTC().Unix(),
		"domain_used":         domainForVerification,
		"original_metadata":   originalMetadata,
		"current_merkle_root": currentMerkleRoot,
		"current_root_hash":   currentRootHash,
		"changes":             changes,
		"root_match":          rootMatch,
		"config_used":         config,
	}

	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	reportFile := "verification_report.json"
	os.WriteFile(reportFile, reportJSON, 0644)
	fmt.Printf("\nVerification report saved to: %s\n", reportFile)

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Merkle Tree File Integrity Verifier with Domain Binding")
		fmt.Println("Version:", Version)
		fmt.Println("Algorithm:", Algorithm)
		fmt.Println("\nUsage:")
		fmt.Println("  mfv hash <folder> [--domain example.com]    - Create Merkle tree for folder")
		fmt.Println("  mfv verify <folder> [--domain example.com]  - Verify folder against saved state")
		fmt.Println("  mfv config                                  - Show current configuration")
		fmt.Println("\nConfiguration file:", ConfigFile)
		fmt.Println("Default exclusions: .well-known/* (EXCEPT .well-known/yubicrypt/), .git/, *.tmp, *.log, etc.")
		fmt.Println("Security Note: Only YubiCrypt certificates from .well-known/yubicrypt/ are included")
		fmt.Println("              All other .well-known/ contents are excluded for security")
		fmt.Println("\nExamples:")
		fmt.Println("  mfv hash ./html_root --domain example.com")
		fmt.Println("  mfv verify ./html_root --domain example.com")
		fmt.Println("  mfv config")
		fmt.Println("\nBy default, metadata is saved/loaded from:", MetadataFile)
		os.Exit(1)
	}

	command := os.Args[1]

	if command == "config" {
		config, err := loadConfig(ConfigFile)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		configJSON, _ := json.MarshalIndent(config, "", "  ")
		fmt.Println("Current configuration:")
		fmt.Println(string(configJSON))

		fmt.Println("\nDefault exclusions:")
		for _, pattern := range defaultConfig.ExcludePatterns {
			fmt.Printf("  Pattern: %s\n", pattern)
		}
		for _, path := range defaultConfig.ExcludePaths {
			fmt.Printf("  Path: %s\n", path)
		}
		fmt.Println("\nSpecial Rule: .well-known/yubicrypt/ is ALWAYS included regardless of exclusions")
		os.Exit(0)
	}

	if len(os.Args) < 3 {
		fmt.Printf("Error: Folder path required for command '%s'\n", command)
		os.Exit(1)
	}

	folderPath := os.Args[2]

	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		fmt.Printf("Error: Folder '%s' does not exist\n", folderPath)
		os.Exit(1)
	}

	config, err := loadConfig(ConfigFile)
	if err != nil {
		fmt.Printf("Warning: Could not load config file: %v\n", err)
		fmt.Println("Using default configuration")
		config = defaultConfig
	}

	metadataFile := MetadataFile
	domain := ""

	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "--domain" && i+1 < len(os.Args) {
			domain = os.Args[i+1]
			i++
		} else if !strings.HasPrefix(os.Args[i], "--") {
			metadataFile = os.Args[i]
		}
	}

	switch command {
	case "hash":
		err := hashFolder(folderPath, metadataFile, config, domain)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
			fmt.Printf("Error: Metadata file '%s' not found\n", metadataFile)
			fmt.Println("Run 'mfv hash' first to create a baseline")
			os.Exit(1)
		}
		err := verifyFolder(folderPath, metadataFile, config, domain)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Available commands: hash, verify, config")
		os.Exit(1)
	}
}
