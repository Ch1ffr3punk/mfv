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
	Root        *MerkleNode
	FileCount   int
	CreatedAt   time.Time
	FolderPath  string
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
	Added      []FileInfo `json:"added"`
	Modified   []FileInfo `json:"modified"`
	Deleted    []FileInfo `json:"deleted"`
	Unchanged  []FileInfo `json:"unchanged"`
	RootMatch  bool       `json:"root_match"`
	Message    string     `json:"message"`
}

// Config for exclusions
type Config struct {
	ExcludePatterns []string `json:"exclude_patterns"`
	ExcludePaths    []string `json:"exclude_paths"`
}

// Default configuration
var defaultConfig = Config{
	ExcludePatterns: []string{
		".well-known/*",           // ACME challenges, security files
		"*.tmp",                   // Temporary files
		"*.log",                   // Log files
		".git/*",                  // Git directory
		".DS_Store",               // macOS metadata
		"Thumbs.db",               // Windows thumbnails
		"merkle_metadata.json",    // Our own metadata file
		"verification_report.json", // Verification reports
		"merkle_config.json",      // Config file
	},
	ExcludePaths: []string{
		".well-known",             // Entire .well-known directory
		".git",                    // Entire .git directory
	},
}

// Constants
const (
	Version      = "0.2.0"  // Updated version
	Algorithm    = "RIPEMD-160"
	MetadataFile = "merkle_metadata.json"
	ConfigFile   = "merkle_config.json"
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

// Check if a path should be excluded
func shouldExclude(path string, relPath string, config Config) bool {
	// Check exact path matches
	for _, excludePath := range config.ExcludePaths {
		if relPath == excludePath || strings.HasPrefix(relPath, excludePath+"/") {
			return true
		}
	}
	
	// Check pattern matches
	for _, pattern := range config.ExcludePatterns {
		matched, _ := filepath.Match(pattern, filepath.Base(relPath))
		if matched {
			return true
		}
		
		// Check for path patterns with directories
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
		// Create default config file
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

// Collect all files in a folder (recursively) with exclusions
func collectFiles(rootPath string, config Config) ([]FileInfo, int64, []string, error) {
	var files []FileInfo
	var totalSize int64
	var excludedPaths []string

	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, 0, nil, err
	}

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if !info.Mode().IsRegular() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}

		// Check if file should be excluded
		if shouldExclude(path, relPath, config) {
			excludedPaths = append(excludedPaths, relPath)
			return nil
		}

		// Calculate file hash
		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hashing %s: %v", path, err)
		}

		// Store file information with UTC time
		fileInfo := FileInfo{
			Path:        relPath,
			Hash:        hash,
			Size:        info.Size(),
			Modified:    info.ModTime().UTC(), // Convert to UTC
			Permissions: getFilePermissions(info.Mode()),
		}

		files = append(files, fileInfo)
		totalSize += info.Size()

		return nil
	})

	// Sort by path for consistent order
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	sort.Strings(excludedPaths)
	return files, totalSize, excludedPaths, err
}

// Create a new Merkle node
func NewMerkleNode(left, right *MerkleNode, hash string) *MerkleNode {
	node := &MerkleNode{}

	if left == nil && right == nil {
		// Leaf node
		node.Hash = hash
	} else {
		// Internal node - combine child hashes
		combined := left.Hash
		if right != nil {
			combined += right.Hash
		}
		node.Hash = calculateRIPEMD160([]byte(combined))
		node.Left = left
		node.Right = right
	}

	return node
}

// Build a Merkle tree from a list of hashes
func NewMerkleTree(fileHashes []string) *MerkleTree {
	if len(fileHashes) == 0 {
		// Handle empty folder
		emptyHash := calculateRIPEMD160([]byte(""))
		return &MerkleTree{
			Root: NewMerkleNode(nil, nil, emptyHash),
		}
	}

	var nodes []MerkleNode

	// Create leaf nodes
	for _, hash := range fileHashes {
		nodes = append(nodes, *NewMerkleNode(nil, nil, hash))
	}

	// If odd number, duplicate last hash
	if len(nodes)%2 == 1 {
		lastNode := nodes[len(nodes)-1]
		nodes = append(nodes, lastNode)
	}

	// Build tree bottom-up
	for len(nodes) > 1 {
		var newLevel []MerkleNode

		for i := 0; i < len(nodes); i += 2 {
			var left, right *MerkleNode
			left = &nodes[i]
			
			if i+1 < len(nodes) {
				right = &nodes[i+1]
			}

			newNode := NewMerkleNode(left, right, "")
			newLevel = append(newLevel, *newNode)
		}

		// If odd number on this level
		if len(newLevel)%2 == 1 && len(newLevel) > 1 {
			lastNode := newLevel[len(newLevel)-1]
			newLevel = append(newLevel, lastNode)
		}

		nodes = newLevel
	}

	return &MerkleTree{
		Root: &nodes[0],
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

	// Create maps for quick lookup
	originalMap := make(map[string]FileInfo)
	currentMap := make(map[string]FileInfo)

	for _, file := range original {
		originalMap[file.Path] = file
	}
	for _, file := range current {
		currentMap[file.Path] = file
	}

	// Check for modified and unchanged files
	for path, currentFile := range currentMap {
		originalFile, exists := originalMap[path]
		if !exists {
			// New file
			result.Added = append(result.Added, currentFile)
		} else {
			if originalFile.Hash != currentFile.Hash {
				// Modified file
				result.Modified = append(result.Modified, currentFile)
			} else {
				// Unchanged file
				result.Unchanged = append(result.Unchanged, currentFile)
			}
		}
	}

	// Check for deleted files
	for path, originalFile := range originalMap {
		if _, exists := currentMap[path]; !exists {
			result.Deleted = append(result.Deleted, originalFile)
		}
	}

	// Sort results for consistent output
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

// Main function for "hash" command
func hashFolder(folderPath string, outputFile string, config Config) error {
	absPath, err := filepath.Abs(folderPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	fmt.Printf("Analyzing folder: %s\n", absPath)
	fmt.Printf("Using configuration: %s\n", ConfigFile)
	fmt.Println("Collecting files and calculating hashes...")

	// Collect files with exclusions
	files, totalSize, excludedPaths, err := collectFiles(absPath, config)
	if err != nil {
		return fmt.Errorf("failed to collect files: %v", err)
	}

	// Extract hashes for Merkle tree
	var hashes []string
	for _, file := range files {
		hashes = append(hashes, file.Hash)
	}

	// Build Merkle tree
	tree := NewMerkleTree(hashes)

	// Create metadata with UTC time
	metadata := &Metadata{
		RootHash:      tree.Root.Hash,
		FolderPath:    absPath,
		CreatedAt:     time.Now().UTC(), // Store as UTC
		FileCount:     len(files),
		TotalSize:     totalSize,
		Files:         files,
		Algorithm:     Algorithm,
		Version:       Version,
		ExcludedPaths: excludedPaths,
	}

	// Save metadata
	err = saveMetadata(metadata, outputFile)
	if err != nil {
		return fmt.Errorf("failed to save metadata: %v", err)
	}

	// Display results
	fmt.Println("Analysis complete!")
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Root Hash:       %s\n", tree.Root.Hash)
	fmt.Printf("  Total Files:     %d (included)\n", len(files))
	fmt.Printf("  Excluded Files:  %d\n", len(excludedPaths))
	fmt.Printf("  Total Size:      %s (included files)\n", formatBytes(totalSize))
	fmt.Printf("  Created At:      %s\n", formatTimeUTC(metadata.CreatedAt))
	fmt.Printf("  Algorithm:       %s\n", Algorithm)
	fmt.Printf("  Metadata saved:  %s\n", outputFile)

	if len(excludedPaths) > 0 {
		fmt.Printf("\nExcluded Paths:\n")
		for _, path := range excludedPaths {
			fmt.Printf("  %s\n", path)
		}
	}

	if len(files) > 0 {
		fmt.Println("\nIncluded File Details:")
		for _, file := range files {
			fmt.Printf("  File: %s\n", file.Path)
			fmt.Printf("    Hash: %s\n", file.Hash)
			fmt.Printf("    Size: %s\n", formatBytes(file.Size))
			fmt.Printf("    Modified: %s\n", formatTimeUTC(file.Modified))
			fmt.Printf("    Permissions: %s\n", file.Permissions)
		}
	}

	return nil
}

// Main function for "verify" command
func verifyFolder(folderPath string, metadataFile string, config Config) error {
	absPath, err := filepath.Abs(folderPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	fmt.Printf("Verifying folder: %s\n", absPath)
	fmt.Printf("Using configuration: %s\n", ConfigFile)

	// Load original metadata
	fmt.Printf("Loading metadata from: %s\n", metadataFile)
	originalMetadata, err := loadMetadata(metadataFile)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %v", err)
	}

	// Check if folder paths match
	if absPath != originalMetadata.FolderPath {
		fmt.Printf("Warning: Folder path differs from original\n")
		fmt.Printf("  Original: %s\n", originalMetadata.FolderPath)
		fmt.Printf("  Current:  %s\n", absPath)
		fmt.Println()
	}

	// Collect current files with same exclusions
	fmt.Println("Analyzing current folder state...")
	currentFiles, currentTotalSize, currentExcludedPaths, err := collectFiles(absPath, config)
	if err != nil {
		return fmt.Errorf("failed to collect current files: %v", err)
	}

	// Extract current hashes
	var currentHashes []string
	for _, file := range currentFiles {
		currentHashes = append(currentHashes, file.Hash)
	}

	// Build current Merkle tree
	currentTree := NewMerkleTree(currentHashes)

	// Compare root hashes
	rootMatch := originalMetadata.RootHash == currentTree.Root.Hash

	// Compare individual files
	changes := compareFiles(originalMetadata.Files, currentFiles)

	// Set result message
	if rootMatch && len(changes.Added) == 0 && len(changes.Modified) == 0 && len(changes.Deleted) == 0 {
		changes.Message = "Folder is UNCHANGED. All included files are identical."
		changes.RootMatch = true
	} else {
		changes.Message = "Folder has been MODIFIED."
		changes.RootMatch = false
	}

	// Display results
	fmt.Printf("\n%s\n", changes.Message)
	fmt.Printf("\nComparison Results:\n")
	fmt.Printf("  Original Root:    %s\n", originalMetadata.RootHash)
	fmt.Printf("  Current Root:     %s\n", currentTree.Root.Hash)
	fmt.Printf("  Root Match:       %v\n", rootMatch)
	fmt.Printf("  Original Created: %s\n", formatTimeUTC(originalMetadata.CreatedAt))
	fmt.Printf("  Verification At:  %s\n", formatTimeUTC(time.Now().UTC()))
	fmt.Printf("  Original Files:   %d (included)\n", len(originalMetadata.Files))
	fmt.Printf("  Current Files:    %d (included)\n", len(currentFiles))
	fmt.Printf("  Original Excluded: %d files\n", len(originalMetadata.ExcludedPaths))
	fmt.Printf("  Current Excluded:  %d files\n", len(currentExcludedPaths))
	fmt.Printf("  Original Size:    %s (included)\n", formatBytes(originalMetadata.TotalSize))
	fmt.Printf("  Current Size:     %s (included)\n", formatBytes(currentTotalSize))

	// Show excluded paths if they differ
	if len(currentExcludedPaths) > 0 {
		fmt.Printf("\nCurrently Excluded Paths (%d):\n", len(currentExcludedPaths))
		for _, path := range currentExcludedPaths {
			fmt.Printf("  %s\n", path)
		}
	}

	// Display changes
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
			// Find original file for comparison
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

	// Save verification report with UTC timestamps
	report := map[string]interface{}{
		"verification_date":    time.Now().UTC().Format(time.RFC3339),
		"verification_unix":    time.Now().UTC().Unix(),
		"original_metadata":    originalMetadata,
		"current_files":        currentFiles,
		"current_excluded":     currentExcludedPaths,
		"changes":              changes,
		"root_match":           rootMatch,
		"config_used":          config,
	}

	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	reportFile := "verification_report.json"
	os.WriteFile(reportFile, reportJSON, 0644)
	fmt.Printf("\nVerification report saved to: %s\n", reportFile)

	return nil
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

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Merkle Tree File Integrity Verifier with Exclusions")
		fmt.Println("Version:", Version)
		fmt.Println("Algorithm:", Algorithm)
		fmt.Println("\nUsage:")
		fmt.Println("  mfv hash <folder>    - Create Merkle tree for folder")
		fmt.Println("  mfv verify <folder>  - Verify folder against saved state")
		fmt.Println("  mfv config           - Show current configuration")
		fmt.Println("\nConfiguration file:", ConfigFile)
		fmt.Println("Default exclusions: .well-known/, .git/, *.tmp, *.log, etc.")
		fmt.Println("\nExamples:")
		fmt.Println("  mfv hash ./html_root")
		fmt.Println("  mfv verify ./html_root")
		fmt.Println("  mfv config")
		fmt.Println("\nBy default, metadata is saved/loaded from:", MetadataFile)
		os.Exit(1)
	}

	command := os.Args[1]
	
	// Handle config command separately
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
		os.Exit(0)
	}
	
	if len(os.Args) < 3 {
		fmt.Printf("Error: Folder path required for command '%s'\n", command)
		os.Exit(1)
	}
	
	folderPath := os.Args[2]

	// Check if folder exists
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		fmt.Printf("Error: Folder '%s' does not exist\n", folderPath)
		os.Exit(1)
	}

	// Load configuration
	config, err := loadConfig(ConfigFile)
	if err != nil {
		fmt.Printf("Warning: Could not load config file: %v\n", err)
		fmt.Println("Using default configuration")
		config = defaultConfig
	}

	// Optional metadata file parameter
	metadataFile := MetadataFile
	if len(os.Args) > 3 {
		metadataFile = os.Args[3]
	}

	switch command {
	case "hash":
		err := hashFolder(folderPath, metadataFile, config)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		// Check if metadata file exists
		if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
			fmt.Printf("Error: Metadata file '%s' not found\n", metadataFile)
			fmt.Println("Run 'mfv hash' first to create a baseline")
			os.Exit(1)
		}
		err := verifyFolder(folderPath, metadataFile, config)
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
