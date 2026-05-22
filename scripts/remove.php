<?php
require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter;

$input = json_decode(file_get_contents('php://stdin'), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die(json_encode(['error' => 'Invalid JSON input']));
}

$code = $input['code'];
$remove = $input['remove'];

$parser = (new ParserFactory)->createForHostVersion();
$prettyPrinter = new PrettyPrinter\Standard();

try {
    $stmts = $parser->parse($code);
} catch (Error $e) {
    die(json_encode(['error' => $e->getMessage()]));
}

$traverser = new NodeTraverser();

class RemoveVisitor extends NodeVisitorAbstract {
    private $remove;
    private $classStack = [];
    private $currentNamespace = '';

    public function __construct($remove) {
        $this->remove = $remove;
    }

    public function enterNode(Node $node) {
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->currentNamespace = $node->name ? $node->name->toString() : '';
        } elseif ($node instanceof Node\Stmt\Class_ || $node instanceof Node\Stmt\Interface_) {
            $className = $node->name->toString();
            $fullClassName = $this->currentNamespace ? $this->currentNamespace . '\\' . $className : $className;
            array_push($this->classStack, $fullClassName);
        }
        return null;
    }

    public function leaveNode(Node $node) {
        if ($node instanceof Node\Stmt\Class_ || $node instanceof Node\Stmt\Interface_) {
            array_pop($this->classStack);
        } elseif ($node instanceof Node\Stmt\Namespace_) {
            $this->currentNamespace = '';
        }

        // Remove classes/interfaces
        if ($node instanceof Node\Stmt\Class_ || $node instanceof Node\stmt\Interface_) {
            $className = $this->currentNamespace ? $this->currentNamespace . '\\' . $node->name->toString() : $node->name->toString();
            if (in_array($className, $this->remove['classes'])) {
                return NodeTraverser::REMOVE_NODE;
            }
        }

        // Remove functions
        if ($node instanceof Node\Stmt\Function_) {
            $funcName = $this->currentNamespace ? $this->currentNamespace . '\\' . $node->name->toString() : $node->name->toString();
            if (in_array($funcName, $this->remove['functions'])) {
                return NodeTraverser::REMOVE_NODE;
            }
        }

        // Remove methods
        if ($node instanceof Node\Stmt\ClassMethod && !empty($this->classStack)) {
            $currentClass = end($this->classStack);
            $methodName = $node->name->toString();
            $isStatic = $node->isStatic();

            $methodsToRemove = $isStatic 
                ? ($this->remove['static_methods'][$currentClass] ?? [])
                : ($this->remove['instance_methods'][$currentClass] ?? []);

            if (in_array($methodName, $methodsToRemove)) {
                return NodeTraverser::REMOVE_NODE;
            }
        }

        // Remove empty classes and interfaces
        if ($node instanceof Node\Stmt\Class_ || $node instanceof Node\Stmt\Interface_) {
            $hasMethods = false;
            foreach ($node->stmts as $stmt) {
                if ($stmt instanceof Node\Stmt\ClassMethod) {
                    $hasMethods = true;
                    break;
                }
            }
            // If no methods and no other members to preserve, remove
            if (!$hasMethods) {
                return NodeTraverser::REMOVE_NODE;
            }
        }

        return null;
    }
}

$traverser->addVisitor(new RemoveVisitor($remove));

try {
    $modifiedStmts = $traverser->traverse($stmts);
} catch (Error $e) {
    die(json_encode(['error' => $e->getMessage()]));
}

$code = $prettyPrinter->prettyPrint($modifiedStmts);

// Ensure the PHP closing tag is present

echo json_encode(['code' => $code]);