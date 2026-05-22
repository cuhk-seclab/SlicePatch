<?php
require __DIR__ . '/vendor/autoload.php';

use PhpParser\{Node, ParserFactory, NodeFinder, Comment, Error, NodeTraverser, NodeVisitorAbstract};

// Global log array
$log = [];


function deep_clone_node(Node $node): Node {
    $traverser = new NodeTraverser();
    // CloningVisitor is not in the use statement group, so use FQN
    $traverser->addVisitor(new \PhpParser\NodeVisitor\CloningVisitor());
    $clonedNodes = $traverser->traverse([$node]);
    return $clonedNodes[0];
}


function collect_all_comments_from_ast(array $ast): array {
    $comments = [];
    $traverser = new NodeTraverser();
    $visitor = new class extends NodeVisitorAbstract {
        public array $comments = [];
        public function enterNode(Node $node) {
            $this->comments = array_merge($this->comments, $node->getComments());
        }
    };
    $traverser->addVisitor($visitor);
    $traverser->traverse($ast);
    return $visitor->comments;
}



function merge_files($originalCode, $patchCode, $originalPath, $patchPath) {
    global $log;
    $log[] = 'Log start time: ' . date('Y-m-d H:i:s');
    $log[] = "==================================================";
    $log[] = "Processing files:";
    $log[] = "  - Original: $originalPath";
    $log[] = "  - Patch:    $patchPath";
    $log[] = "==================================================";

    // Use a parser that can handle comments
    $parser = (new ParserFactory)->createForHostVersion();
    $printer = new PhpParser\PrettyPrinter\Standard();

    try {
        $log[] = "Parsing original file...";
        $originalAst = $parser->parse($originalCode);
        $log[] = "Parsing patch file...";
        $patchAst = $parser->parse($patchCode);
    } catch (Error $e) {
        $log[] = "Error: PHP parsing failed: " . $e->getMessage();
        throw new Exception("PHP parsing error: " . $e->getMessage());
    }

    // Check if a full replacement is needed
    if (should_fully_replace($originalAst, $patchAst)) {
        $log[] = "Decision: Full replacement. No class or function declarations found in either file.";
        
        $allOriginalComments = collect_all_comments_from_ast($originalAst);
        $log[] = "Collected and preserving " . count($allOriginalComments) . " comments from the original file.";

        // Attach all original comments to the top of the patch AST
        if (!empty($patchAst) && !empty($allOriginalComments)) {
            $firstNode = $patchAst[0];
            $existingComments = $firstNode->getComments();
            // Put original comments first
            $firstNode->setAttribute('comments', array_merge($allOriginalComments, $existingComments));
            $log[] = "Attached " . count($allOriginalComments) . " original comments to the top of the patch file.";
        } elseif (empty($patchAst) && !empty($allOriginalComments)) {
            // If patch file is empty but there are comments to preserve
            $commentStr = "";
            foreach ($allOriginalComments as $comment) {
                $commentStr .= $comment->getText() . "\n";
            }
            $log[] = "Patch file is empty, outputting only original comments.";
            return "<?php\n" . $commentStr;
        }
        
        return $printer->prettyPrintFile($patchAst);
    }

    $log[] = "Decision: Merging based on AST.";
    $mergedAst = merge_classes_and_functions($originalAst, $patchAst);

    $log[] = "Merge complete, generating final code.";
    return $printer->prettyPrintFile($mergedAst);
}

function should_fully_replace($originalAst, $patchAst) {
    $nodeFinder = new NodeFinder();
    
    $hasDeclarations = function($ast) use ($nodeFinder) {
        return !empty($nodeFinder->find($ast, function(Node $node) {
            return $node instanceof Node\Stmt\Class_ ||
                   $node instanceof Node\Stmt\Interface_ ||
                   $node instanceof Node\Stmt\Trait_ ||
                   $node instanceof Node\Stmt\Function_;
        }));
    };
    
    // If neither file has class, function, or method declarations, then replace fully.
    return !$hasDeclarations($originalAst) && !$hasDeclarations($patchAst);
}


function get_node_without_comments(Node $node): Node {
    $cleanNode = deep_clone_node($node);
    
    $traverser = new NodeTraverser();
    $visitor = new class extends NodeVisitorAbstract {
        public function enterNode(Node $node) {
            $node->setAttribute('comments', []);
        }
    };
    $traverser->addVisitor($visitor);
    $traverser->traverse([$cleanNode]);
    
    return $cleanNode;
}

function nodes_are_identical_ignore_comments(Node $node1, Node $node2) {
    // Create copies of the nodes with comments removed.
    $cleanNode1 = get_node_without_comments($node1);
    $cleanNode2 = get_node_without_comments($node2);

    // Use PrettyPrinter to compare string representations.
    $printer = new PhpParser\PrettyPrinter\Standard();
    return $printer->prettyPrint([$cleanNode1]) === $printer->prettyPrint([$cleanNode2]);
}


function merge_statements(array $originalStmts, array $patchStmts, array &$log, string $contextLogPrefix): array {
    if (empty($originalStmts)) {
        if (!empty($patchStmts)) {
            $log[] = "{$contextLogPrefix}: Original method body is empty, using all " . count($patchStmts) . " statements from patch.";
        }
        return $patchStmts;
    }
    if (empty($patchStmts)) {
        $log[] = "{$contextLogPrefix}: Patch method body is empty, method is cleared.";
        return [];
    }

    $printer = new PhpParser\PrettyPrinter\Standard();
    
    // Create a map of original statements using their code as keys.
    $originalStmtsMap = [];
    foreach ($originalStmts as $stmt) {
        $cleanNode = get_node_without_comments($stmt);
        $code = $printer->prettyPrint([$cleanNode]);
        // Handle potential hash collisions by storing an array of nodes.
        if (!isset($originalStmtsMap[$code])) {
            $originalStmtsMap[$code] = [];
        }
        $originalStmtsMap[$code][] = $stmt;
    }

    $mergedStmts = [];
    $unchanged_count = 0;
    $changed_count = 0;

    foreach ($patchStmts as $patchStmt) {
        $cleanPatchNode = get_node_without_comments($patchStmt);
        $patchCode = $printer->prettyPrint([$cleanPatchNode]);

        // Check if an identical statement exists in the original map.
        if (isset($originalStmtsMap[$patchCode]) && !empty($originalStmtsMap[$patchCode])) {
            // Identical statement found. Use the original node to preserve comments.
            // Dequeue the found statement to handle duplicates correctly.
            $originalNode = array_shift($originalStmtsMap[$patchCode]);
            $mergedStmts[] = $originalNode;
            $unchanged_count++;
        } else {
            // This is a new or modified statement. Use the patch version.
            $mergedStmts[] = $patchStmt;
            $changed_count++;
        }
    }
    
    $log[] = "{$contextLogPrefix}: Statement merge complete. Kept {$unchanged_count} unchanged statements (with comments), used/added {$changed_count} statements from patch.";

    return $mergedStmts;
}

function merge_classes_and_functions($originalAst, $patchAst) {
    global $log;
    $nodeFinder = new NodeFinder();
    $mergedAst = $originalAst;
    
    // Process functions
    $patchFunctions = $nodeFinder->find($patchAst, function(Node $node) {
        return $node instanceof Node\Stmt\Function_;
    });
    
    foreach ($patchFunctions as $patchFunc) {
        $found = false;
        $funcName = $patchFunc->name ? $patchFunc->name->name : '[Anonymous Function]';

        foreach ($mergedAst as $index => &$originalNode) {
            if ($originalNode instanceof Node\Stmt\Function_ && 
                $originalNode->name && $patchFunc->name &&
                $originalNode->name->name === $patchFunc->name->name) {
                
                // Check if functions are identical (ignoring comments)
                if (!nodes_are_identical_ignore_comments($originalNode, $patchFunc)) {
                    $log_msg = "Function '{$funcName}' has differences, replacing.";
                    
                    // Different, replace with patch version but keep all original function comments
                    $replacement = deep_clone_node($patchFunc);
                    // Get only comments directly associated with the node, not all children
                    $originalComments = $originalNode->getComments();
                    $replacement->setAttribute('comments', $originalComments);
                    
                    $log_msg .= " Preserved " . count($originalComments) . " top-level comments.";
                    $log[] = $log_msg;
                    
                    // Statement-level merge
                    $originalStmts = $originalNode->stmts ?? [];
                    $patchStmts = $patchFunc->stmts ?? [];
                    $replacement->stmts = merge_statements($originalStmts, $patchStmts, $log, "Function '{$funcName}'");

                    $mergedAst[$index] = $replacement;
                } else {
                    $log[] = "Function '{$funcName}' is identical, keeping original version.";
                }
                $found = true;
                break;
            }
        }
        if (!$found) {
            // Add new function
            $log[] = "Found new function '{$funcName}', adding.";
            $mergedAst[] = $patchFunc;
        }
    }
    
    // Process classes
    $patchClasses = $nodeFinder->find($patchAst, function(Node $node) {
        return $node instanceof Node\Stmt\Class_ ||
               $node instanceof Node\Stmt\Interface_ ||
               $node instanceof Node\Stmt\Trait_;
    });
    
    foreach ($patchClasses as $patchClass) {
        $found = false;
        $className = $patchClass->name ? $patchClass->name->name : '[Anonymous Class]';

        foreach ($mergedAst as $index => &$originalNode) {
            if (($originalNode instanceof Node\Stmt\Class_ || 
                 $originalNode instanceof Node\Stmt\Interface_ || 
                 $originalNode instanceof Node\Stmt\Trait_) && 
                $originalNode->name && $patchClass->name &&
                $originalNode->name->name === $patchClass->name->name) {
                
                $log[] = "Merging contents of class '{$className}'...";
                // Merge class contents
                $mergedClass = merge_class_contents($originalNode, $patchClass);
                $mergedAst[$index] = $mergedClass;
                $found = true;
                break;
            }
        }
        if (!$found) {
            // Add new class
            $log[] = "Found new class '{$className}', adding.";
            $mergedAst[] = $patchClass;
        }
    }
    
    // Process other top-level statements (not functions or classes)
    // This is crucial for handling patches that modify top-level code
    $log[] = "Processing top-level statements (non-function/class code)...";
    $mergedAst = merge_statements($originalAst, $patchAst, $log, "Top-level statements");
    
    return $mergedAst;
}

function merge_class_contents(Node $originalClass, Node $patchClass) {
    global $log;
    $mergedClass = deep_clone_node($originalClass);
    $className = $originalClass->name ? $originalClass->name->name : '[Anonymous Class]';
    
    // Preserve comments of the class declaration itself
    // Get only comments directly associated with the node, not all children
    $originalComments = $originalClass->getComments();
    $mergedClass->setAttribute('comments', $originalComments);
    $log[] = "Preserved " . count($originalComments) . " top-level comments for class '{$className}'.";
    
    // Create member map
    $originalMembers = [];
    foreach ($originalClass->stmts as $stmt) {
        $key = get_member_key($stmt);
        if ($key) {
            $originalMembers[$key] = $stmt;
        }
    }
    
    $mergedStmts = $originalClass->stmts;

    // Process members from the patch
    foreach ($patchClass->stmts as $patchStmt) {
        $key = get_member_key($patchStmt);
        
        if ($key && isset($originalMembers[$key])) {
            // Member exists in original class
            $originalStmt = $originalMembers[$key];
            
            // Check if members are identical (ignoring comments)
            if (!nodes_are_identical_ignore_comments($originalStmt, $patchStmt)) {
                $log_msg = "Member '{$key}' in class '{$className}' has differences, replacing.";
                
                $replacement = null;

                // For methods, perform statement-level merge to preserve internal comments
                if ($originalStmt instanceof Node\Stmt\ClassMethod && $patchStmt instanceof Node\Stmt\ClassMethod) {
                    $replacement = deep_clone_node($patchStmt);
                    
                    // Preserve top-level comments of the original method
                    $originalMemberComments = $originalStmt->getComments();
                    $replacement->setAttribute('comments', $originalMemberComments);
                    $log_msg .= " Preserved " . count($originalMemberComments) . " top-level comments.";
                    
                    // Merge method body statements
                    $originalStmts = $originalStmt->stmts ?? [];
                    $patchStmts = $patchStmt->stmts ?? [];
                    $replacement->stmts = merge_statements($originalStmts, $patchStmts, $log, "Member '{$key}' in class '{$className}'");
                } 
                // For properties, constants, etc., replace the node directly but preserve its top-level comments
                else {
                    $replacement = deep_clone_node($patchStmt);
                    $originalMemberComments = $originalStmt->getComments();
                    $replacement->setAttribute('comments', $originalMemberComments);
                    $log_msg .= " Preserved " . count($originalMemberComments) . " original comments.";
                }
                
                $log[] = $log_msg;

                // Replace in the merged list
                foreach ($mergedStmts as $i => &$member) {
                    if ($member === $originalStmt) {
                        $mergedStmts[$i] = $replacement;
                        break;
                    }
                }
            } else {
                $log[] = "Member '{$key}' in class '{$className}' is identical, keeping original version.";
            }
        } else {
            // New member, add directly
            if ($key) {
                $log[] = "Found new member '{$key}' in class '{$className}', adding.";
            } else {
                $log[] = "Found an unrecognized new member in class '{$className}', adding.";
            }
            $mergedStmts[] = $patchStmt;
        }
    }
    
    $mergedClass->stmts = $mergedStmts;
    return $mergedClass;
}

function get_member_key($node) {
    if ($node instanceof Node\Stmt\ClassMethod) {
        return 'Method:' . $node->name->name;
    }
    if ($node instanceof Node\Stmt\Property) {
        return 'Property:' . $node->props[0]->name->name;
    }
    if ($node instanceof Node\Stmt\ClassConst) {
        return 'Constant:' . $node->consts[0]->name->name;
    }
    if ($node instanceof Node\Stmt\TraitUse) {
        $traits = [];
        foreach ($node->traits as $trait) {
            $traits[] = $trait->toString();
        }
        return 'TraitUse:' . implode(',', $traits);
    }
    return null;
}

// Command line processing
if (isset($argv[1]) && isset($argv[2])) {
    $originalPath = $argv[1];
    $patchPath = $argv[2];
    $outputPath = $argv[3] ?? $originalPath; // Default to overwriting the original file
    
    try {
        if (!file_exists($originalPath)) {
            throw new Exception("Original file not found: $originalPath");
        }
        if (!file_exists($patchPath)) {
            throw new Exception("Patch file not found: $patchPath");
        }
        
        $originalCode = file_get_contents($originalPath);
        $patchCode = file_get_contents($patchPath);
        $result = merge_files($originalCode, $patchCode, $originalPath, $patchPath);
        file_put_contents($outputPath, $result);

        $log[] = "Patch successfully applied to: $outputPath";
        echo "Patch successfully applied to: $outputPath\n";
        echo "Detailed log written to /tmp/patch_php.log\n";

    } catch (Exception $e) {
        $log[] = "Fatal error: " . $e->getMessage();
        die("Error: " . $e->getMessage() . "\n");
    } finally {
        // Ensure the log is always written
        file_put_contents('/tmp/patch_php.log', implode("\n", $log) . "\n");
    }
} else {
    die("Usage: php patch.php <original_file> <patch_file> [output_file]\n");
}
//