<?php
require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;

class CommentCleaner extends NodeVisitorAbstract {
    public function leaveNode(\PhpParser\Node $node) {
        if ($node->getAttribute('comments') !== null) {
            $comments = $node->getAttribute('comments');
            $filteredComments = array_filter($comments, function($comment) {
                return strpos($comment->getText(), '[Artificial]') !== false;
            });
            if (empty($filteredComments)) {
                $node->setAttribute('comments', []);
            }
        }
        
        // Clear PHPDoc comments
        if ($node->getDocComment() !== null) {
            $node->setDocComment(new \PhpParser\Comment\Doc(''));
        }
        
        return $node;
    }
}

$input = file_get_contents('php://stdin');
$parser = (new ParserFactory)->createForHostVersion();
$traverser = new NodeTraverser();
$traverser->addVisitor(new CommentCleaner());
$printer = new Standard();
$output = [];
$error = '';

try {
    $ast = $parser->parse($input);
    $ast = $traverser->traverse($ast);
    $output[] = $printer->prettyPrint($ast);
} catch (Error $e) {
    $error .= $e->getMessage() . "\n";
    $output[] = $input; // Return original input on parsing failure
}

echo json_encode([
    'code' => implode("\n", $output),
    'error' => $error
]);