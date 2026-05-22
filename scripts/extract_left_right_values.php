<?php
require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\NodeDumper;
use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

class LeftRightValueExtractor extends NodeVisitorAbstract {
    private $left_values = [];
    private $right_values = [];
    private $assignments = [];
    
    public function enterNode(\PhpParser\Node $node) {
        // Handle assignment expressions (AST_ASSIGN)
        if ($node instanceof \PhpParser\Node\Expr\Assign) {
            $left = $this->extractVariableName($node->var);
            $right = $this->extractVariableName($node->expr);
            
            if ($left && $right) {
                $this->assignments[] = $left . '=' . $right;
            }
            if ($left) {
                $this->left_values[] = $left . '=';
            }
            if ($right) {
                $this->right_values[] = '&' . $right;
            }
        }
        
        // Handle if condition expressions
        elseif ($node instanceof \PhpParser\Node\Stmt\If_) {
            if ($node->cond instanceof \PhpParser\Node\Expr\BinaryOp) {
                $left = $this->extractVariableName($node->cond->left);
                $right = $this->extractVariableName($node->cond->right);
                
                if ($left && $right) {
                    $this->assignments[] = $left . '=' . $right;
                }
                if ($left) {
                    $this->left_values[] = $left . '&';
                }
                if ($right) {
                    $this->right_values[] = '&' . $right;
                }
            }
        }
        
        // Handle while loop conditions
        elseif ($node instanceof \PhpParser\Node\Stmt\While_) {
            if ($node->cond instanceof \PhpParser\Node\Expr\BinaryOp) {
                $left = $this->extractVariableName($node->cond->left);
                $right = $this->extractVariableName($node->cond->right);
                
                if ($left && $right) {
                    $this->assignments[] = $left . '=' . $right;
                }
                if ($left) {
                    $this->left_values[] = $left . '&';
                }
                if ($right) {
                    $this->right_values[] = '&' . $right;
                }
            }
        }
        
        // Handle for loops
        elseif ($node instanceof \PhpParser\Node\Stmt\For_) {
            foreach ($node->init as $init) {
                if ($init instanceof \PhpParser\Node\Expr\Assign) {
                    $left = $this->extractVariableName($init->var);
                    $right = $this->extractVariableName($init->expr);
                    
                    if ($left && $right) {
                        $this->assignments[] = $left . '=' . $right;
                    }
                    if ($left) {
                        $this->left_values[] = $left . '&';
                    }
                    if ($right) {
                        $this->right_values[] = '&' . $right;
                    }
                }
            }
        }
        
        // Handle function call arguments
        elseif ($node instanceof \PhpParser\Node\Expr\FuncCall) {
            foreach ($node->args as $arg) {
                $value = $this->extractVariableName($arg->value);
                if ($value) {
                    $this->right_values[] = '&' . $value;
                }
            }
        }
        
        // Handle method call arguments
        elseif ($node instanceof \PhpParser\Node\Expr\MethodCall) {
            foreach ($node->args as $arg) {
                $value = $this->extractVariableName($arg->value);
                if ($value) {
                    $this->right_values[] = '&' . $value;
                }
            }
        }
    }
    
    private function extractVariableName($node) {
        if ($node instanceof \PhpParser\Node\Expr\Variable) {
            if (is_string($node->name)) {
                return $node->name;
            }
        } elseif ($node instanceof \PhpParser\Node\Expr\ArrayDimFetch) {
            $arrayName = $this->extractVariableName($node->var);
            if ($node->dim instanceof \PhpParser\Node\Scalar\String_) {
                return $arrayName . '[' . $node->dim->value . ']';
            }
        } elseif ($node instanceof \PhpParser\Node\Scalar\String_) {
            return $node->value;
        } elseif ($node instanceof \PhpParser\Node\Scalar\LNumber) {
            return (string)$node->value;
        }
        return null;
    }
    
    public function getLeftValues() {
        return array_unique($this->left_values);
    }
    
    public function getRightValues() {
        return array_unique($this->right_values);
    }
    
    public function getAssignments() {
        return array_unique($this->assignments);
    }
}

// Check command line arguments
if ($argc < 3) {
    echo "Usage: php extract_left_right_values.php <slice_directory> <output_file> [poc_data_file]\n";
    exit(1);
}

$slice_dir = $argv[1];
$output_file = $argv[2];
$poc_data_file = isset($argv[3]) ? $argv[3] : null;

// Read POC request data
$poc_request_data = [];
if ($poc_data_file && file_exists($poc_data_file)) {
    $poc_json = file_get_contents($poc_data_file);
    $poc_request_data = json_decode($poc_json, true);
    if ($poc_request_data === null) {
        echo "Warning: Could not parse POC data file: {$poc_data_file}\n";
        $poc_request_data = [];
    } else {
        echo "Loaded POC request data from: {$poc_data_file}\n";
    }
} else {
    echo "No POC data file provided or file does not exist, using defaults\n";
}

// Extract POC data or use default values
$target_url = isset($poc_request_data['url']) ? $poc_request_data['url'] : 'http://localhost/slice_analysis';
$request_method = isset($poc_request_data['method']) ? $poc_request_data['method'] : 'GET';
$request_params = isset($poc_request_data['params']) ? $poc_request_data['params'] : [];
$crash_fields = isset($poc_request_data['crash_fields']) ? $poc_request_data['crash_fields'] : [];

echo "Target URL: {$target_url}\n";
echo "Request method: {$request_method}\n";
echo "Request params: " . json_encode($request_params) . "\n";
echo "Crash fields: " . json_encode($crash_fields) . "\n";

// Check if input directory exists
if (!is_dir($slice_dir)) {
    echo "Error: Slice directory '{$slice_dir}' does not exist.\n";
    exit(1);
}

$all_left_values = [];
$all_right_values = [];
$all_assignments = [];

// Recursively find all PHP files
$php_files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($slice_dir),
    RecursiveIteratorIterator::LEAVES_ONLY
);

$processed_files = 0;
$total_files = 0;

// First count the number of files
foreach ($php_files as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $total_files++;
    }
}

// Re-create iterator to process files
$php_files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($slice_dir),
    RecursiveIteratorIterator::LEAVES_ONLY
);

foreach ($php_files as $file) {
    if ($file->isFile() && $file->getExtension() === 'php' && $file->getFilename() !== 'full_slice.php') {
        $processed_files++;
        echo "Processing file [{$processed_files}/{$total_files}]: " . $file->getPathname() . "\n";
        
        $code = file_get_contents($file->getPathname());
        
        $parser = (new ParserFactory)->createForHostVersion();
        
        try {
            $ast = $parser->parse($code);
            
            $extractor = new LeftRightValueExtractor();
            $traverser = new NodeTraverser();
            $traverser->addVisitor($extractor);
            $traverser->traverse($ast);
            
            $all_left_values = array_merge($all_left_values, $extractor->getLeftValues());
            $all_right_values = array_merge($all_right_values, $extractor->getRightValues());
            $all_assignments = array_merge($all_assignments, $extractor->getAssignments());
            
        } catch (Error $error) {
            echo "Parse error in file " . $file->getPathname() . ": {$error->getMessage()}\n";
        }
    }
}

// Merge all extracted values with predefined XSS payloads
$predefined_xss_payloads = [
    '&<script>alert(290363);</script>',
    '&<SCRIPT>alert(290363);</SCRIPT>',  
    '&\"><SCRIPT>alert(290363);</SCRIPT>'
];

$input_set = array_merge(
    array_unique($all_left_values),
    array_unique($all_right_values),
    array_unique($all_assignments),
    array_unique($predefined_xss_payloads)
);

// Generate request key name
$request_key = $request_method . ' ' . $target_url;

// Process request parameters, generate pivotal_input_set in k=v format
$pivotal_input_set = [];
$post_payload = '';
$full_url = $target_url;

if (!empty($request_params)) {
    foreach ($request_params as $key => $value) {
        // Add k=v format to pivotal_input_set
        $pivotal_input_set[] = $key . '=' . $value;
    }
    
    if (strtoupper($request_method) === 'POST') {
        // POST method: generate POST payload
        $post_payload = '&' . http_build_query($request_params);
    } else {
        // GET method: append parameters to URL
        $query_string = http_build_query($request_params);
        if (!empty($query_string)) {
            $separator = (strpos($target_url, '?') !== false) ? '&' : '?';
            $full_url = $target_url . $separator . $query_string;
        }
    }
}

// Generate request_data.json format
$request_entry = [
    '_id' => 1,
    '_url' => $full_url,
    '_method' => $request_method,
    'key' => $request_key,
    '_pivotal_input_set' => $pivotal_input_set
];

// Only add _postData field for POST method
if (strtoupper($request_method) === 'POST' && !empty($post_payload)) {
    $request_entry['_postData'] = $post_payload;
}

$request_data = [
    'requestsFound' => [
        $request_key => $request_entry
    ],
    'inputSet' => $input_set
];

// Ensure output directory exists
$output_dir = dirname($output_file);
if (!is_dir($output_dir)) {
    mkdir($output_dir, 0755, true);
}

// Write to file
if (file_put_contents($output_file, json_encode($request_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))) {
    echo "Left/right values extracted and saved to: " . $output_file . "\n";
    echo "Total input set items: " . count($input_set) . "\n";
    echo "Total assignments: " . count(array_unique($all_assignments)) . "\n";
    echo "Total left values: " . count(array_unique($all_left_values)) . "\n";
    echo "Total right values: " . count(array_unique($all_right_values)) . "\n";
    echo "Files processed: {$processed_files}\n";
} else {
    echo "Error: Failed to write output file: " . $output_file . "\n";
    exit(1);
}
?>
