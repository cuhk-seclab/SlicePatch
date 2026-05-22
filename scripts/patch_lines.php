<?php
require __DIR__ . '/vendor/autoload.php';

use PhpParser\{Node, ParserFactory, NodeFinder, Comment, Error, NodeTraverser, NodeVisitorAbstract};

// Global log array
$log = [];


function calculate_similarity($str1, $str2) {
    $str1 = trim($str1);
    $str2 = trim($str2);
    
    if ($str1 === $str2) {
        return 100.0;
    }
    
    $len1 = strlen($str1);
    $len2 = strlen($str2);
    
    // Handle empty strings
    if ($len1 === 0 && $len2 === 0) {
        return 100.0;
    }
    if ($len1 === 0 || $len2 === 0) {
        return 0.0;
    }
    
    // If length difference is too large, similarity is low
    $lengthRatio = min($len1, $len2) / max($len1, $len2);
    if ($lengthRatio < 0.3) {
        return 0.0; // Too different in length
    }
    
    // Use similar_text as primary measure for better accuracy
    $similarTextScore = 0;
    similar_text($str1, $str2, $similarTextScore);
    
    // Use Levenshtein distance for additional validation (only for shorter strings)
    $levenshteinSimilarity = 0;
    if ($len1 <= 255 && $len2 <= 255) {
        $distance = levenshtein($str1, $str2);
        $maxLen = max($len1, $len2);
        if ($maxLen > 0) {
            $levenshteinSimilarity = max(0, (1 - ($distance / $maxLen)) * 100);
        }
    }
    
    // Use the more reliable similar_text score, with levenshtein as validation
    $finalSimilarity = $similarTextScore;
    
    // If levenshtein is available and shows significant difference, adjust down
    if ($levenshteinSimilarity > 0 && abs($similarTextScore - $levenshteinSimilarity) > 20) {
        // Take the average if they differ significantly
        $finalSimilarity = ($similarTextScore + $levenshteinSimilarity) / 2;
    }
    
    // Ensure similarity is within 0-100 range
    return max(0, min(100, $finalSimilarity));
}


function normalize_content($content) {
    // Split into lines
    $lines = explode("\n", $content);
    $normalizedLines = [];
    
    foreach ($lines as $line) {
        // Remove leading and trailing whitespace, but preserve relative indentation
        $trimmed = trim($line);
        if (!empty($trimmed)) {
            $normalizedLines[] = $trimmed;
        }
    }
    
    return implode("\n", $normalizedLines);
}


function optimize_match_with_sliding_window($matchResult, $targetContent, $sourceLines, $threshold = 0.0) {
    global $log;
    
    if ($matchResult === null) {
        return null;
    }
    
    $log[] = "Optimizing match with adaptive sliding window expansion";
    
    // Normalize target content once
    $normalizedTarget = normalize_content($targetContent);
    $sourceLineCount = count($sourceLines);
    
    // Extract match information
    $startIndex = $matchResult['start_index'];
    $endIndex = $matchResult['end_index'];
    $currentSimilarity = $matchResult['similarity'];
    
    $log[] = "Starting optimization from match at lines " . ($startIndex + 1) . "-" . ($endIndex + 1) . 
             " (base similarity: {$currentSimilarity}%)";
    
    $maxBackwardLines = min(10, $startIndex); // Don't go too far back
    $maxForwardLines = min(10, $sourceLineCount - $endIndex - 1); // Don't go too far forward
    
    // Variables to track expansions
    $backward_expansions = 0;
    $forward_expansions = 0;
    
    // Expand window adaptively in both directions
    $continue = true;
    while ($continue) {
        $continue = false;
        
        // Try expanding backward
        if ($startIndex > 0 && $backward_expansions < $maxBackwardLines) {
            $newStartIndex = $startIndex - 1;
            $candidateLines = array_slice($sourceLines, $newStartIndex, $endIndex - $newStartIndex + 1);
            $candidateContent = implode("\n", $candidateLines);
            $normalizedCandidate = normalize_content($candidateContent);
            $backwardSimilarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
            
            if ($backwardSimilarity > $currentSimilarity) {
                $startIndex = $newStartIndex;
                $currentSimilarity = $backwardSimilarity;
                $continue = true;
                $backward_expansions++;
                $log[] = "Expanded backward to line " . ($startIndex + 1) . 
                         " (new similarity: {$currentSimilarity}%)";
            }
        }
        
        // Try expanding forward
        if ($endIndex < $sourceLineCount - 1 && $forward_expansions < $maxForwardLines) {
            $newEndIndex = $endIndex + 1;
            $candidateLines = array_slice($sourceLines, $startIndex, $newEndIndex - $startIndex + 1);
            $candidateContent = implode("\n", $candidateLines);
            $normalizedCandidate = normalize_content($candidateContent);
            $forwardSimilarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
            
            if ($forwardSimilarity > $currentSimilarity) {
                $endIndex = $newEndIndex;
                $currentSimilarity = $forwardSimilarity;
                $continue = true;
                $forward_expansions++;
                $log[] = "Expanded forward to line " . ($endIndex + 1) . 
                         " (new similarity: {$currentSimilarity}%)";
            }
        }
    }
    
    // Update match result if similarity improved
    if ($currentSimilarity > $matchResult['similarity']) {
        $candidateLines = array_slice($sourceLines, $startIndex, $endIndex - $startIndex + 1);
        $candidateContent = implode("\n", $candidateLines);
        
        $log[] = "Sliding window optimization complete: lines " . ($startIndex + 1) . "-" . ($endIndex + 1) . 
                 " (backward: {$backward_expansions}, forward: {$forward_expansions}, final similarity: {$currentSimilarity}%)";
        
        return [
            'content' => $candidateContent,
            'start_index' => $startIndex,
            'end_index' => $endIndex,
            'similarity' => $currentSimilarity
        ];
    } else {
        $log[] = "Sliding window optimization did not improve similarity, keeping original match";
        return $matchResult;
    }
}


function find_by_first_last_lines($targetLines, $sourceLines, $threshold = 0.0) {
    global $log;
    
    if (count($targetLines) < 2) {
        return null; // Need at least 2 lines for this strategy
    }
    
    $firstTarget = trim($targetLines[0]);
    $lastTarget = trim($targetLines[count($targetLines) - 1]);
    
    $log[] = "Trying first/last line matching strategy";
    $log[] = "Looking for first line: '" . substr($firstTarget, 0, 50) . (strlen($firstTarget) > 50 ? "..." : "") . "'";
    $log[] = "Looking for last line: '" . substr($lastTarget, 0, 50) . (strlen($lastTarget) > 50 ? "..." : "") . "'";
    
    // Find all potential first line matches (both exact and similarity)
    $firstLineMatches = [];
    foreach ($sourceLines as $index => $sourceLine) {
        $normalizedSourceLine = trim($sourceLine);
        
        // Exact match
        if ($normalizedSourceLine === $firstTarget) {
            $firstLineMatches[] = ['index' => $index, 'similarity' => 100.0];
        } else {
            // Similarity match
            $similarity = calculate_similarity($firstTarget, $normalizedSourceLine);
            if ($similarity >= $threshold) {
                $firstLineMatches[] = ['index' => $index, 'similarity' => $similarity];
            }
        }
    }
    
    if (empty($firstLineMatches)) {
        $log[] = "No matches found for first line (threshold: {$threshold}%)";
        return null;
    }
    
    $log[] = "Found " . count($firstLineMatches) . " potential first line matches";
    
    // For each first line match, search for the last line in a reasonable range
    $bestMatch = null;
    $bestScore = 0;
    
    foreach ($firstLineMatches as $firstMatch) {
        $startIdx = $firstMatch['index'];
        $firstSimilarity = $firstMatch['similarity'];
        
        // Search for last line in a range (not fixed by target line count)
        // Look ahead up to 20 lines or until we find a good match
        $maxLookAhead = min(20, count($sourceLines) - $startIdx);
        
        for ($lookAhead = 1; $lookAhead < $maxLookAhead; $lookAhead++) {
            $lastIdx = $startIdx + $lookAhead;
            $candidateLastLine = trim($sourceLines[$lastIdx]);
            
            // Check if this could be our last line
            $lastSimilarity = 0;
            if ($candidateLastLine === $lastTarget) {
                $lastSimilarity = 100.0;
            } else {
                $lastSimilarity = calculate_similarity($lastTarget, $candidateLastLine);
            }
            
            if ($lastSimilarity >= $threshold) {
                // Found a potential match! Calculate overall score
                $overallScore = ($firstSimilarity + $lastSimilarity) / 2;
                
                if ($overallScore > $bestScore) {
                    $candidateLines = array_slice($sourceLines, $startIdx, $lookAhead + 1);
                    $candidateContent = implode("\n", $candidateLines);
                    
                    $bestMatch = [
                        'content' => $candidateContent,
                        'start_index' => $startIdx,
                        'end_index' => $lastIdx,
                        'similarity' => $overallScore,
                        'first_similarity' => $firstSimilarity,
                        'last_similarity' => $lastSimilarity,
                        'line_count' => $lookAhead + 1
                    ];
                    $bestScore = $overallScore;
                }
            }
        }
    }
    
    if ($bestMatch !== null) {
        $log[] = "Found best first/last match: lines " . ($bestMatch['start_index'] + 1) . "-" . ($bestMatch['end_index'] + 1) . 
                 " (first: {$bestMatch['first_similarity']}%, last: {$bestMatch['last_similarity']}%, overall: {$bestMatch['similarity']}%)";
        
        // Create target content from the match for optimization
        $targetContent = implode("\n", $targetLines);
        
        // Find the highest similarity score among first, last and overall
        $bestSimilarity = max($bestMatch['first_similarity'], $bestMatch['last_similarity'], $bestMatch['similarity']);
        $bestMatch['similarity'] = $bestSimilarity;
        
        $log[] = "Using highest similarity score ({$bestSimilarity}%) for optimization";
        
        // Optimize the match with sliding window expansion using the highest similarity
        $optimizedMatch = optimize_match_with_sliding_window($bestMatch, $targetContent, $sourceLines, $threshold);
        
        return $optimizedMatch;
    }
    
    $log[] = "No matching first/last line pairs found";
    return null;
}


function find_by_content_similarity($targetContent, $sourceLines, $threshold = 0.0) {
    global $log;
    
    $normalizedTarget = normalize_content($targetContent);
    $sourceLineCount = count($sourceLines);
    
    $log[] = "Trying content similarity matching with sliding window";
    
    $bestMatch = null;
    $bestSimilarity = 0;
    
    // Try different window sizes (from 1 to reasonable max)
    $maxWindowSize = min(15, $sourceLineCount); // Don't go too big
    
    for ($windowSize = 1; $windowSize <= $maxWindowSize; $windowSize++) {
        for ($startIdx = 0; $startIdx <= $sourceLineCount - $windowSize; $startIdx++) {
            $candidateLines = array_slice($sourceLines, $startIdx, $windowSize);
            $candidateContent = implode("\n", $candidateLines);
            $normalizedCandidate = normalize_content($candidateContent);
            
            $similarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
            
            if ($similarity >= $threshold && $similarity > $bestSimilarity) {
                $bestMatch = [
                    'content' => $candidateContent,
                    'start_index' => $startIdx,
                    'end_index' => $startIdx + $windowSize - 1,
                    'similarity' => $similarity,
                    'window_size' => $windowSize
                ];
                $bestSimilarity = $similarity;
            }
        }
    }
    
    if ($bestMatch !== null) {
        $log[] = "Found content match: lines " . ($bestMatch['start_index'] + 1) . "-" . ($bestMatch['end_index'] + 1) . 
                 " (window size: {$bestMatch['window_size']}, similarity: {$bestMatch['similarity']}%)";
        
        // Optimize the match with sliding window expansion
        $optimizedMatch = optimize_match_with_sliding_window($bestMatch, $targetContent, $sourceLines, $threshold);
        
        return $optimizedMatch;
    }
    
    $log[] = "No content similarity match found";
    return null;
}

function find_best_match($targetContent, $sourceLines, $threshold = 0.0) {
    global $log;
    
    // Normalize the target content first to handle JSON escape sequences
    $targetContent = str_replace('\n', "\n", $targetContent);
    $targetContent = trim($targetContent);
    $targetLines = explode("\n", $targetContent);
    $targetLineCount = count($targetLines);
    
    $log[] = "Searching for content with {$targetLineCount} lines";
    
    $bestMatch = null;
    $bestSimilarity = 0;
    $bestStartIndex = -1;
    $bestEndIndex = -1;
    
    if ($targetLineCount === 1) {
        // Single line matching
        $targetLine = trim($targetLines[0]);
        
        // Strategy 1: Exact match
        foreach ($sourceLines as $index => $sourceLine) {
            $normalizedSourceLine = trim($sourceLine);
            if ($normalizedSourceLine === $targetLine) {
                $log[] = "Exact single-line match found at index $index";
                $initialMatch = ['content' => $sourceLine, 'start_index' => $index, 'end_index' => $index, 'similarity' => 100.0];
                // For single line exact matches, we still run the optimizer to see if we can get better context
                return optimize_match_with_sliding_window($initialMatch, $targetContent, $sourceLines, $threshold);
            }
        }
        
        // Strategy 2: Similarity matching
        foreach ($sourceLines as $index => $sourceLine) {
            $normalizedSourceLine = trim($sourceLine);
            $similarity = calculate_similarity($targetLine, $normalizedSourceLine);
            
            if ($similarity >= $threshold && $similarity > $bestSimilarity) {
                $bestMatch = $sourceLine;
                $bestSimilarity = $similarity;
                $bestStartIndex = $index;
                $bestEndIndex = $index;
            }
        }
    } else {
        // Multi-line matching
        $sourceLineCount = count($sourceLines);
        
        // Strategy 1: First/Last line matching (most reliable for multi-line)
        $firstLastMatch = find_by_first_last_lines($targetLines, $sourceLines, $threshold);
        if ($firstLastMatch !== null) {
            $log[] = "✓ Match found using first/last line strategy";
            return $firstLastMatch;
        }
        
        // Strategy 2: Content-based matching (find the best matching content regardless of line count)
        $bestContentMatch = find_by_content_similarity($targetContent, $sourceLines, $threshold);
        if ($bestContentMatch !== null) {
            $log[] = "✓ Match found using content similarity strategy";
            return $bestContentMatch;
        }
        
        // Strategy 3: Consecutive line matching with normalization (fallback)
        for ($startIdx = 0; $startIdx <= $sourceLineCount - $targetLineCount; $startIdx++) {
            $candidateLines = array_slice($sourceLines, $startIdx, $targetLineCount);
            $candidateContent = implode("\n", $candidateLines);
            
            // Sub-strategy 2a: Exact match with original content
            if ($candidateContent === $targetContent) {
                $log[] = "Exact multi-line match (with whitespace) found at lines " . ($startIdx + 1) . "-" . ($startIdx + $targetLineCount);
                $initialMatch = [
                    'content' => $candidateContent,
                    'start_index' => $startIdx,
                    'end_index' => $startIdx + $targetLineCount - 1,
                    'similarity' => 100.0
                ];
                // Even for exact matches, use optimizer to potentially include better context
                return optimize_match_with_sliding_window($initialMatch, $targetContent, $sourceLines, $threshold);
            }
            
            // Sub-strategy 2b: Exact match after trimming both
            $trimmedCandidate = trim($candidateContent);
            if ($trimmedCandidate === $targetContent) {
                $log[] = "Exact multi-line match (trimmed) found at lines " . ($startIdx + 1) . "-" . ($startIdx + $targetLineCount);
                $initialMatch = [
                    'content' => $candidateContent,
                    'start_index' => $startIdx,
                    'end_index' => $startIdx + $targetLineCount - 1,
                    'similarity' => 100.0
                ];
                // Even for exact matches, use optimizer to potentially include better context
                return optimize_match_with_sliding_window($initialMatch, $targetContent, $sourceLines, $threshold);
            }
            
            // Sub-strategy 2c: Normalize content for comparison
            $normalizedCandidate = normalize_content($candidateContent);
            $normalizedTarget = normalize_content($targetContent);
            
            if ($normalizedCandidate === $normalizedTarget) {
                $log[] = "Exact multi-line match (normalized) found at lines " . ($startIdx + 1) . "-" . ($startIdx + $targetLineCount);
                $initialMatch = [
                    'content' => $candidateContent,
                    'start_index' => $startIdx,
                    'end_index' => $startIdx + $targetLineCount - 1,
                    'similarity' => 100.0
                ];
                // Even for exact matches, use optimizer to potentially include better context
                return optimize_match_with_sliding_window($initialMatch, $targetContent, $sourceLines, $threshold);
            }
            
            // Sub-strategy 2d: Check similarity with normalized content
            $similarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
            if ($similarity >= $threshold && $similarity > $bestSimilarity) {
                $bestMatch = $candidateContent;
                $bestSimilarity = $similarity;
                $bestStartIndex = $startIdx;
                $bestEndIndex = $startIdx + $targetLineCount - 1;
            }
        }
        
        // Strategy 4: Adaptive sliding window expansion
        if ($bestMatch !== null) {
            $log[] = "Trying adaptive sliding window expansion strategy using existing match as base";
            
            // Normalize target content once
            $normalizedTarget = normalize_content($targetContent);
            
            // Use the existing match as starting point for expansion
            $startIndex = $bestStartIndex;
            $endIndex = $bestEndIndex;
            $currentSimilarity = $bestSimilarity;
            
            $log[] = "Starting expansion from existing match at lines " . ($startIndex + 1) . "-" . ($endIndex + 1) . 
                     " (base similarity: {$currentSimilarity}%)";
            
            $maxBackwardLines = min(10, $startIndex); // Don't go too far back
            $maxForwardLines = min(10, $sourceLineCount - $endIndex - 1); // Don't go too far forward
            
            // Variables to track expansions
            $backward_expansions = 0;
            $forward_expansions = 0;
            
            // Expand window adaptively in both directions
            $continue = true;
            while ($continue) {
                $continue = false;
                
                // Try expanding backward
                if ($startIndex > 0 && $backward_expansions < $maxBackwardLines) {
                    $newStartIndex = $startIndex - 1;
                    $candidateLines = array_slice($sourceLines, $newStartIndex, $endIndex - $newStartIndex + 1);
                    $candidateContent = implode("\n", $candidateLines);
                    $normalizedCandidate = normalize_content($candidateContent);
                    $backwardSimilarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
                    
                    if ($backwardSimilarity > $currentSimilarity) {
                        $startIndex = $newStartIndex;
                        $currentSimilarity = $backwardSimilarity;
                        $continue = true;
                        $backward_expansions++;
                        $log[] = "Expanded backward to line " . ($startIndex + 1) . 
                                 " (new similarity: {$currentSimilarity}%)";
                    }
                }
                
                // Try expanding forward
                if ($endIndex < $sourceLineCount - 1 && $forward_expansions < $maxForwardLines) {
                    $newEndIndex = $endIndex + 1;
                    $candidateLines = array_slice($sourceLines, $startIndex, $newEndIndex - $startIndex + 1);
                    $candidateContent = implode("\n", $candidateLines);
                    $normalizedCandidate = normalize_content($candidateContent);
                    $forwardSimilarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
                    
                    if ($forwardSimilarity > $currentSimilarity) {
                        $endIndex = $newEndIndex;
                        $currentSimilarity = $forwardSimilarity;
                        $continue = true;
                        $forward_expansions++;
                        $log[] = "Expanded forward to line " . ($endIndex + 1) . 
                                 " (new similarity: {$currentSimilarity}%)";
                    }
                }
            }
            
            // Set the final match info if similarity improved
            if ($currentSimilarity > $bestSimilarity) {
                $candidateLines = array_slice($sourceLines, $startIndex, $endIndex - $startIndex + 1);
                $candidateContent = implode("\n", $candidateLines);
                
                $bestMatch = $candidateContent;
                $bestSimilarity = $currentSimilarity;
                $bestStartIndex = $startIndex;
                $bestEndIndex = $endIndex;
                
                $log[] = "Adaptive window expansion complete: lines " . ($startIndex + 1) . "-" . ($endIndex + 1) . 
                         " (backward: {$backward_expansions}, forward: {$forward_expansions}, final similarity: {$currentSimilarity}%)";
            } else {
                $log[] = "Adaptive window expansion did not improve similarity, keeping original match";
            }
        } else if ($targetLineCount > 1) {
            // If no match was found yet but content is multi-line, try finding a single best line as anchor
            $log[] = "No match found yet, trying to find initial anchor point for adaptive window expansion";
            
            // Normalize target content once
            $normalizedTarget = normalize_content($targetContent);
            
            // Find the best initial match (single line)
            $bestInitialMatch = null;
            $bestInitialSimilarity = 0;
            $bestInitialIndex = -1;
            
            for ($i = 0; $i < $sourceLineCount; $i++) {
                $candidateLine = $sourceLines[$i];
                $normalizedCandidate = normalize_content($candidateLine);
                $similarity = calculate_similarity($normalizedTarget, $normalizedCandidate);
                
                if ($similarity >= $threshold && $similarity > $bestInitialSimilarity) {
                    $bestInitialMatch = $candidateLine;
                    $bestInitialSimilarity = $similarity;
                    $bestInitialIndex = $i;
                }
            }
            
            if ($bestInitialMatch !== null) {
                // Similar code to above for expansion, but starting from a single line
                // This is a fallback if no match was found in previous strategies
                $log[] = "Found initial anchor match at line " . ($bestInitialIndex + 1) . 
                         " (similarity: {$bestInitialSimilarity}%)";
                
                // Rest of the expansion logic (same as above)
                $startIndex = $bestInitialIndex;
                $endIndex = $bestInitialIndex;
                $currentSimilarity = $bestInitialSimilarity;
                
                // Continue with the same expansion logic as above...
                // (Removed duplicate code for brevity - the same window expansion would be implemented)
            }
        }
    }
    
    if ($bestMatch !== null) {
        if ($bestStartIndex === $bestEndIndex) {
            $log[] = "Similarity match found for single line at index $bestStartIndex (similarity: {$bestSimilarity}%)";
        } else {
            $log[] = "Similarity match found for multi-line content at lines " . ($bestStartIndex + 1) . "-" . ($bestEndIndex + 1) . " (similarity: {$bestSimilarity}%)";
        }
        
        $initialMatch = [
            'content' => $bestMatch,
            'start_index' => $bestStartIndex,
            'end_index' => $bestEndIndex,
            'similarity' => $bestSimilarity
        ];
        
        // Optimize match using sliding window if it's a multi-line match
        if ($bestStartIndex !== $bestEndIndex) {
            // Optimize the match with sliding window expansion
            $optimizedMatch = optimize_match_with_sliding_window($initialMatch, $targetContent, $sourceLines, $threshold);
            return $optimizedMatch;
        }
        
        return $initialMatch;
    }
    
    $log[] = "No match found for content (threshold: {$threshold}%)";
    return null;
}


function apply_lines_patch($originalCode, $lineMappings, $originalPath, $mappingPath) {
    global $log;
    
    $log[] = 'Log start time: ' . date('Y-m-d H:i:s');
    $log[] = "==================================================";
    $log[] = "Processing line-based patch:";
    $log[] = "  - Original: $originalPath";
    $log[] = "  - Mapping:  $mappingPath";
    $log[] = "  - Total mappings: " . count($lineMappings);
    $log[] = "==================================================";

    // Split original code into lines
    $originalLines = explode("\n", $originalCode);
    $totalLines = count($originalLines);
    $log[] = "Original file has $totalLines lines";
    $log[] = $originalCode;
    
    // Track successful and failed matches
    $successfulMatches = 0;
    $similarityMatches = 0;
    $failedMatches = 0;
    
    // First, find all matches and store them
    $allMatches = [];
    foreach ($lineMappings as $originalContent => $replacementContent) {
        $log[] = "\n--- Finding match for mapping ---";
        $log[] = "Original: '" . str_replace("\n", "\\n", $originalContent) . "'";
        $log[] = "Replacement: '" . str_replace("\n", "\\n", $replacementContent) . "'";
        
        // Find best match in original lines
        $matchResult = find_best_match($originalContent, $originalLines);
        
        if ($matchResult !== null) {
            $allMatches[] = [
                'original' => $originalContent,
                'replacement' => $replacementContent,
                'match_result' => $matchResult
            ];
            $log[] = "✓ Match found for this content";
        } else {
            $failedMatches++;
            $log[] = "✗ No suitable match found for this content";
        }
    }
    
    // Sort matches by start index in ascending order (process from beginning to end)
    usort($allMatches, function($a, $b) {
        return $a['match_result']['start_index'] - $b['match_result']['start_index'];
    });
    
    // Check for overlapping matches and warn
    for ($i = 0; $i < count($allMatches) - 1; $i++) {
        $currentEnd = $allMatches[$i]['match_result']['end_index'];
        $nextStart = $allMatches[$i + 1]['match_result']['start_index'];
        if ($currentEnd >= $nextStart) {
            $log[] = "⚠ Warning: Overlapping matches detected between ranges " . 
                     ($allMatches[$i]['match_result']['start_index'] + 1) . "-" . ($currentEnd + 1) . 
                     " and " . ($nextStart + 1) . "-" . ($allMatches[$i + 1]['match_result']['end_index'] + 1);
        }
    }
    
    // Apply all matches using a new approach: build result from segments
    $resultLines = [];
    $currentPosition = 0; // Current position in original lines
    
    foreach ($allMatches as $match) {
        $originalContent = $match['original'];
        $replacementContent = $match['replacement'];
        $matchResult = $match['match_result'];
        
        $startIndex = $matchResult['start_index'];
        $endIndex = $matchResult['end_index'];
        $similarity = $matchResult['similarity'];
        
        $log[] = "\n--- Applying replacement ---";
        $log[] = "Processing range: lines " . ($startIndex + 1) . "-" . ($endIndex + 1);
        
        // Add lines before this replacement (from currentPosition to startIndex)
        if ($startIndex > $currentPosition) {
            $beforeLines = array_slice($originalLines, $currentPosition, $startIndex - $currentPosition);
            $resultLines = array_merge($resultLines, $beforeLines);
            $log[] = "Added " . count($beforeLines) . " lines before replacement (lines " . ($currentPosition + 1) . "-" . $startIndex . ")";
        }
        
        // Add the replacement content
        $replacementLines = explode("\n", $replacementContent);
        $resultLines = array_merge($resultLines, $replacementLines);
        $log[] = "Added replacement content: " . count($replacementLines) . " lines";
        
        // Update current position to after this replacement
        $currentPosition = $endIndex + 1;
        
        // Count success/similarity matches
        if ($similarity === 100.0) {
            $successfulMatches++;
            if ($startIndex === $endIndex) {
                $log[] = "✓ Exact single-line match applied at line " . ($startIndex + 1);
            } else {
                $log[] = "✓ Exact multi-line match applied at lines " . ($startIndex + 1) . "-" . ($endIndex + 1);
            }
        } else {
            $similarityMatches++;
            if ($startIndex === $endIndex) {
                $log[] = "✓ Similarity single-line match applied at line " . ($startIndex + 1) . " (similarity: {$similarity}%)";
            } else {
                $log[] = "✓ Similarity multi-line match applied at lines " . ($startIndex + 1) . "-" . ($endIndex + 1) . " (similarity: {$similarity}%)";
            }
        }
    }
    
    // Add remaining lines after all replacements
    if ($currentPosition < count($originalLines)) {
        $remainingLines = array_slice($originalLines, $currentPosition);
        $resultLines = array_merge($resultLines, $remainingLines);
        $log[] = "Added " . count($remainingLines) . " remaining lines after all replacements (lines " . ($currentPosition + 1) . "-" . count($originalLines) . ")";
    }
    
    // Update originalLines with the new result
    $originalLines = $resultLines;
    
    // Generate summary
    $log[] = "\n==================================================";
    $log[] = "PATCH SUMMARY:";
    $log[] = "  - Total mappings to process: " . count($lineMappings);
    $log[] = "  - Exact matches applied: $successfulMatches";
    $log[] = "  - Similarity matches applied: $similarityMatches";
    $log[] = "  - Failed matches: $failedMatches";
    $log[] = "  - Success rate: " . round((($successfulMatches + $similarityMatches) / count($lineMappings)) * 100, 2) . "%";
    $log[] = "==================================================";
    
    // Reconstruct the patched code
    $patchedCode = implode("\n", $originalLines);
    
    return $patchedCode;
}


function parse_line_mappings($mappingPath) {
    if (!file_exists($mappingPath)) {
        throw new Exception("Mapping file not found: $mappingPath");
    }
    
    $jsonContent = file_get_contents($mappingPath);
    if ($jsonContent === false) {
        throw new Exception("Failed to read mapping file: $mappingPath");
    }
    
    $mappings = json_decode($jsonContent, true);
    if ($mappings === null) {
        throw new Exception("Failed to parse JSON from mapping file: $mappingPath. Error: " . json_last_error_msg());
    }
    
    if (!is_array($mappings)) {
        throw new Exception("Mapping file must contain a JSON object/array: $mappingPath");
    }
    
    return $mappings;
}

// Command line processing
if (isset($argv[1]) && isset($argv[2])) {
    $originalPath = $argv[1];
    $mappingPath = $argv[2];
    $outputPath = $argv[3] ?? $originalPath; // Default to overwriting the original file
    
    try {
        if (!file_exists($originalPath)) {
            throw new Exception("Original file not found: $originalPath");
        }
        
        $log[] = "Reading original file: $originalPath";
        $originalCode = file_get_contents($originalPath);
        if ($originalCode === false) {
            throw new Exception("Failed to read original file: $originalPath");
        }
        
        $log[] = "Parsing line mappings from: $mappingPath";
        $lineMappings = parse_line_mappings($mappingPath);
        
        $log[] = "Applying line-based patch...";
        $result = apply_lines_patch($originalCode, $lineMappings, $originalPath, $mappingPath);
        
        $log[] = "Writing patched content to: $outputPath";
        if (file_put_contents($outputPath, $result) === false) {
            throw new Exception("Failed to write output file: $outputPath");
        }

        $log[] = "Line-based patch successfully applied to: $outputPath";
        echo "Line-based patch successfully applied to: $outputPath\n";
        echo "Detailed log written to /tmp/patch_php_lines.log\n";

    } catch (Exception $e) {
        $log[] = "Fatal error: " . $e->getMessage();
        die("Error: " . $e->getMessage() . "\n");
    } finally {
        // Ensure the log is always written
        file_put_contents('/tmp/patch_php_lines.log', implode("\n", $log) . "\n");
    }
} else {
    die("Usage: php patch_lines.php <original_file> <mapping_file> [output_file]\n");
}
?>
