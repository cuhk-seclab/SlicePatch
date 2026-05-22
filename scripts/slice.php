<?php
require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Property;
use PhpParser\Node\Stmt\PropertyProperty;
use PhpParser\Node\Stmt\Function_;

class SlicingVisitor extends NodeVisitorAbstract
{
    private $fileSlicingInfo;
    private $currentClass;

    public function __construct($fileSlicingInfo)
    {
        $this->fileSlicingInfo = $fileSlicingInfo;
        $this->currentClass = null;
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : null;
        }
        return null;
    }

    public function leaveNode(Node $node)
    {
        // Handle class nodes
        if ($node instanceof Class_) {
            $className = $node->name ? $node->name->toString() : null;
            $this->currentClass = null;

            if (!$className || !isset($this->fileSlicingInfo['classes'][$className])) {
                return NodeTraverser::REMOVE_NODE;
            }
            return $node;
        }

        // Handle class methods
        if ($node instanceof ClassMethod && $this->currentClass) {
            $methodName = $node->name->toString();
            $classInfo = $this->fileSlicingInfo['classes'][$this->currentClass] ?? null;

            if ($classInfo) {
                $keepMethod = false;
                foreach ($classInfo['methods'] as $method) {
                    if ($method[0] === $methodName) {
                        $keepMethod = true;
                        break;
                    }
                }
                if (!$keepMethod) {
                    return NodeTraverser::REMOVE_NODE;
                }
            }
            return $node;
        }

        // Handle class properties
        if ($node instanceof Property && $this->currentClass) {
            $classInfo = $this->fileSlicingInfo['classes'][$this->currentClass] ?? null;

            if ($classInfo) {
                $propertiesToKeep = $classInfo['properties'];
                $newProps = [];

                foreach ($node->props as $prop) {
                    if ($prop instanceof PropertyProperty) {
                        $propName = $prop->name->toString();
                        if (in_array($propName, $propertiesToKeep)) {
                            $newProps[] = $prop;
                        }
                    }
                }

                if (empty($newProps)) {
                    return NodeTraverser::REMOVE_NODE;
                }
                $node->props = $newProps;
            }
            return $node;
        }

        // Handle top-level functions
        if ($node instanceof Function_) {
            $funcName = $node->name->toString();
            $funcsToKeep = $this->fileSlicingInfo['funcs'] ?? [];

            $keepFunction = false;
            foreach ($funcsToKeep as $func) {
                if ($func[0] === $funcName) {
                    $keepFunction = true;
                    break;
                }
            }

            if (!$keepFunction) {
                return NodeTraverser::REMOVE_NODE;
            }
            return $node;
        }

        return null;
    }
}

function filterTopLevelStmts($stmts, $linesToKeep)
{
    $newStmts = [];

    foreach ($stmts as $stmt) {
        if ($stmt instanceof Stmt\Namespace_) {
            $stmt->stmts = filterTopLevelStmts($stmt->stmts, $linesToKeep);
            $newStmts[] = $stmt;
        } elseif (
            $stmt instanceof Class_ || $stmt instanceof Function_ ||
            $stmt instanceof Stmt\Use_ || $stmt instanceof Stmt\GroupUse
        ) {
            $newStmts[] = $stmt;
        } else {
            $startLine = $stmt->getStartLine();
            $endLine = $stmt->getEndLine();
            $keep = false;

            foreach ($linesToKeep as $line) {
                if ($line >= $startLine && $line <= $endLine) {
                    $keep = true;
                    break;
                }
            }

            if ($keep) {
                $newStmts[] = $stmt;
            }
        }
    }

    return $newStmts;
}

// Main processing
$input = file_get_contents('php://stdin');
$inputData = json_decode($input, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die(json_encode(['error' => 'Invalid JSON input: ' . json_last_error_msg()]));
}

$output = [];
$parserFactory = new ParserFactory();
$parser = (new ParserFactory)->createForHostVersion();
$prettyPrinter = new Standard();

foreach ($inputData as $filePath => $slicingInfo) {
    try {
        if (!file_exists($filePath)) {
            throw new Exception("File not found: $filePath");
        }

        $code = file_get_contents($filePath);
        $ast = $parser->parse($code);

        // First pass: Remove unwanted classes/methods/properties
        $traverser = new NodeTraverser();
        $visitor = new SlicingVisitor($slicingInfo);
        $traverser->addVisitor($visitor);
        $ast = $traverser->traverse($ast);

        // Second pass: Filter top-level statements
        $ast = filterTopLevelStmts($ast, $slicingInfo['lines'] ?? []);

        // Generate sliced code
        $newCode = $prettyPrinter->prettyPrintFile($ast);
        $output[$filePath] = ['code' => $newCode, 'error' => null];
    } catch (Exception $e) {
        $output[$filePath] = ['code' => '', 'error' => $e->getMessage()];
    } catch (Error $e) {
        $output[$filePath] = ['code' => '', 'error' => 'Parse error: ' . $e->getMessage()];
    }
}

echo json_encode($output);
