use rustc_hash::FxHashMap;
pub mod regex {
    use super::*;
    pub fn get_regex_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_regex_query".to_string(), QUERIES_REGEX.to_string());
        queries
    }
}
pub mod bash {
    use super::*;
    pub fn get_bash_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_bash_query".to_string(), QUERIES_BASH.to_string());
        queries
    }
}
pub mod c {
    use super::*;
    pub fn get_c_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_c_query".to_string(), QUERIES_C.to_string());
        queries
    }
}
pub mod cpp {
    use super::*;
    pub fn get_cpp_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_cpp_query".to_string(), QUERIES_CPP.to_string());
        queries
    }
}
pub mod css {
    use super::*;
    pub fn get_css_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_css_query".to_string(), QUERIES_CSS.to_string());
        queries
    }
}
pub mod csharp {
    use super::*;
    pub fn get_csharp_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_csharp_query".to_string(), QUERIES_CSHARP.to_string());
        queries
    }
}
pub mod ruby {
    use super::*;
    pub fn get_ruby_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_ruby_query".to_string(), QUERIES_RUBY.to_string());
        queries
    }
}
pub mod rust {
    use super::*;
    pub fn get_rust_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_rust_query".to_string(), QUERIES_RUST.to_string());
        queries
    }
}
pub mod yaml {
    use super::*;
    pub fn get_yaml_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_yaml_query".to_string(), QUERIES_YAML.to_string());
        queries
    }
}
pub mod go {
    use super::*;
    pub fn get_go_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_go_query".to_string(), QUERIES_GO.to_string());
        queries
    }
}
pub mod html {
    use super::*;
    pub fn get_html_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_html_query".to_string(), QUERIES_HTML.to_string());
        queries
    }
}
pub mod java {
    use super::*;
    pub fn get_java_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_java_query".to_string(), QUERIES_JAVA.to_string());
        queries
    }
}
pub mod javascript {
    use super::*;
    pub fn get_javascript_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_javascript_query".to_string(), QUERIES_JAVASCRIPT.to_string());
        queries
    }
}
pub mod kotlin {
    use super::*;
    pub fn get_kotlin_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_kotlin_query".to_string(), QUERIES_KOTLIN.to_string());
        queries
    }
}
pub mod php {
    use super::*;
    pub fn get_php_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_php_query".to_string(), QUERIES_PHP.to_string());
        queries
    }
}
pub mod python {
    use super::*;
    pub fn get_python_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_python_query".to_string(), QUERIES_PYTHON.to_string());
        queries
    }
}
pub mod toml {
    use super::*;
    pub fn get_toml_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_toml_query".to_string(), QUERIES_TOML.to_string());
        queries
    }
}
pub mod typescript {
    use super::*;
    pub fn get_typescript_queries() -> FxHashMap<String, String> {
        let mut queries = FxHashMap::default();
        queries.insert("combined_typescript_query".to_string(), QUERIES_TYPESCRIPT.to_string());
        queries
    }
}
////////////////////////////////////////////////////////
///
pub const QUERIES_REGEX: &str = r#"
(
    (non_capturing_group
        (pattern
            (alternation)
        )
    )
    (anonymous_capturing_group
        (pattern) @key
    )
    (boundary_assertion)? @boundary
)
"#;
pub const QUERIES_BASH: &str = r#"
    (variable_assignment
		name: (variable_name) @key
		value: [(string)(word)] @val
	)
"#;
pub const QUERIES_C: &str = r#"
    ; Query 1: Matches variable declarations with string literal initializations
    (declaration 
        declarator: (init_declarator
            declarator: (identifier) @key
            value: (string_literal) @val
        )
    )

    ; Query 2: Matches pointer variable declarations with string literal initializations
    (declaration 
        declarator: (init_declarator
            declarator: (pointer_declarator
                declarator: (identifier) @key
            )
            value: (string_literal) @val
        )
    )

    ; Query 3: Matches assignments to variables, pointers, or struct fields with string literals
    (assignment_expression 
        left: [(identifier)(pointer_expression)(field_expression)] @key
        right: (string_literal) @val
    )

    ; Query 4: Matches function calls with an identifier and string literal as arguments
    (call_expression
        function: (identifier)
        arguments: (argument_list
            (identifier) @key
            (string_literal) @val
        )
    )

    ; Query 5: Matches struct initializations with field designators and string literal values
    (initializer_pair
        designator: (field_designator
            (field_identifier) @key
        )
        value: (string_literal) @val
    )

    ; Query 6: Matches struct declarations with pointer fields
    (declaration
        type: (struct_specifier
            body: (field_declaration_list
                (field_declaration
                    declarator: (pointer_declarator
                        declarator: (field_identifier) @key
                    )
                )
            )
        )
    )

    ; Query 7: Matches initializer lists containing string literals
    declarator: (init_declarator
        value: (initializer_list
            (string_literal) @val
        )
    )

    ; Query 8: Matches function calls with string literal arguments
    (call_expression
        function: (identifier) @key
        arguments: (argument_list
            (string_literal) @val
        )
    )

    ; Query 9: Matches array declarations with string literal initializations
    (declaration 
        declarator: (init_declarator
            declarator: (array_declarator
                declarator: (identifier) @key
            )
            value: (string_literal) @val
        )
    )
"#;
pub const QUERIES_CPP: &str = r#"
    ; Query 1: Matches string declarations with literal initializations
    ; Example: string s1 = "a string written here";
    (declaration 
        declarator: (init_declarator
            declarator: (identifier) @key
            value: (string_literal) @val
        )
    )

    ; Query 2: Matches char pointer declarations with string literal initializations
    ; Example: char *line = "a string written here";
    (declaration 
        declarator: (init_declarator
            declarator: (pointer_declarator
                declarator: (identifier) @key
            )
            value: (string_literal) @val
        )
    )

    ; Query 3: Matches assignments to variables or object fields with string literals
    ; Examples: s1 = "a string written here";
    ;           myObj.myString = "Some text";
    (assignment_expression 
        left: [(identifier)(field_expression)] @key
        right: (string_literal) @val
    )

    ; Query 4: Matches assignments to dereferenced pointers with string literals
    ; Example: *msg = "a string here";
    (assignment_expression 
        left: (pointer_expression
            argument: (identifier) @key
        )
        right: (string_literal) @val
    )

    ; Query 5: Matches string declarations with character and count initializations
    ; Example: string s6 (15,'*');
    (declaration 
        declarator: (init_declarator
                declarator: (identifier) @key
                value: (argument_list
                (char_literal) @val
            )
        )
    )

    ; Query 6: Matches function calls with identifier and string literal arguments
    ; Example: strcpy(str, "this is a test");
    (call_expression
        function: (identifier)
        arguments: (argument_list
            (identifier) @key
            (string_literal) @val
        )
    )

    ; Query 7: Matches class field declarations with string literal default values
    ; Example: string model = "test string 1";
    (field_declaration
        declarator: (field_identifier) @key
        default_value: (string_literal) @val
    )

    ; Query 8: Matches class field declarations of char pointers with string literal default values
    ; Example: char *ch = "another test string";
    (field_declaration
        declarator: (pointer_declarator
            declarator: (field_identifier) @key
        )
        default_value: (string_literal) @val
    )

    ; Query 9: Matches function calls with string literal arguments
    ; Example: SomeFunction("Passing a string");
    (call_expression
        function: (identifier) @key
        arguments: (argument_list
            (string_literal) @val
        )
    )

    ; Query 10: Matches char array declarations with string literal initializations
    ; Example: char my_str[] = "Hello";
    (declaration 
        declarator: (init_declarator
            declarator: (array_declarator
                declarator: (identifier) @key
            )
            value: (string_literal) @val
        )
    )

    ; Query 11: Matches struct initializer pairs with string literal values
    ; Example: .password = "@pple123"
    (initializer_pair
        designator: (field_designator
            (field_identifier) @key
        )
        value: (string_literal) @val
    )

    ; Query 12: Matches struct declarations with char pointer fields and string literal initializations
    ; Example: char* password; (in struct definition)
    ;          employee_default = {0, "29304!@$#201u3242"}; (in struct initialization)
    (declaration
        type: (struct_specifier
            body: (field_declaration_list
                (field_declaration
                    declarator: (pointer_declarator
                        declarator: (field_identifier) @key
                    )
                )
            )
        )
        declarator: (init_declarator
            value: (initializer_list
                (string_literal) @val
            )
        )
    )
"#;
pub const QUERIES_CSS: &str = r#"
    ; Query 1: Matches CSS declarations with string values
    (declaration
        (property_name) @key
        (string_value) @val
    )

    ; Query 2: Matches CSS declarations with function calls
    (declaration
        (property_name) @key
         (call_expression
            (arguments
                (plain_value) @val
            )
        )
    )
"#;
pub const QUERIES_RUST: &str = r#"
    ; Query 1: Matches let declarations with function calls containing string literal arguments
    ; Example: let my_string = String::from("Hello, world!");
    (let_declaration
        pattern: (identifier) @key
        value: (_
            arguments: (arguments
                (string_literal) @val
            )
        )
    )

    ; Query 2: Matches assignments to struct fields with function calls containing string literal arguments
    ; Example: self.name = String::from("John Doe");
    (assignment_expression
        left: (_
            field: (field_identifier) @key
        )
        right: (call_expression
            arguments: (arguments
                (string_literal) @val
            )
        )
    )

    ; Query 3: Matches let declarations with direct string literal assignments
    ; Example: let greeting = "Hello, Rust!";
    (let_declaration
        pattern: (identifier) @key
        value: (string_literal) @val
    )

    ; Query 4: Matches let declarations with macro invocations or other complex initializations
    ; Example: let formatted = format!("Hello, {}!", name);
    (let_declaration
        pattern: (identifier) @key
        value: (_
            (token_tree) @val
        )
    )
"#;
pub const QUERIES_YAML: &str = r#"
    ; Query 1: Matches key-value pairs in YAML block mappings
    ; Examples:
    ;   key: value
    ;   another_key: "quoted value"
    ;   third_key: 'single quoted value'
    (block_mapping_pair
        key: (flow_node
            [(plain_scalar)(string_scalar)] @key
        )
        value: (flow_node
            [(plain_scalar)(string_scalar)(single_quote_scalar)(double_quote_scalar)] @val
        )
    )
"#;
pub const QUERIES_CSHARP: &str = r#"
    ; Query 1: Matches assignments to object properties
    ; Example: obj.PropertyName = "value";
    (assignment_expression
        left: (member_access_expression
            name: (identifier) @key
        )
        right: (string_literal) @val
    )

    ; Query 2: Matches variable declarations with object creation and string argument
    ; Example: var obj = new SomeClass("string value");
    (variable_declarator
        (identifier) @key
          (object_creation_expression
              arguments: (argument_list
                  (argument
                      (string_literal) @val
                  )
              )
          
      )
    )

    ; Query 3: Matches variable declarations with string literals, verbatim strings, or interpolated strings
    ; Examples: 
    ;   string str = "Hello";
    ;   string verbatim = @"C:\path\to\file";
    ;   string interpolated = $"Hello, {name}";
    (variable_declaration
        (variable_declarator
            name: (identifier) @key
                [(string_literal)(verbatim_string_literal)(interpolated_string_expression)] @val
            
        )
    )

    ; Query 4: Matches variable declarations with string literal in an initializer expression
    ; Example: SomeType var = new SomeType { StringProp = "value" };
    (assignment_expression
        left: (identifier) @key
        right: (string_literal) @val
    )
"#;
pub const QUERIES_RUBY: &str = r#"
    ; Assignment with identifier or instance variable
    (assignment
        left: [(identifier)(instance_variable)] @key
        right: [(string)(integer)] @val
    )
    
    ; Operator assignment
    (operator_assignment
        left: (identifier) @key
        right: [(string)(integer)] @val
    )
    
    ; Assignment with method call on left side
    (assignment
        left: (call
            method: (identifier) @key
        )
        right: [(string)(integer)] @val
    )
    
    ; Assignment with right_assignment_list
    (assignment
        left: (identifier) @key
        right: (right_assignment_list
            [(string)(integer)] @val
        )
    )
    
    ; Assignment with method call and string argument
    (assignment
        left: (identifier) @key
        right: (call
            arguments: (argument_list
                (string
                    (string_content) @val
                )
            )
        )
    )
    
    ; Assignment with constant
    (assignment
        left: (constant) @key
        right: [(string)(integer)] @val
    )
    
    ; Method call with receiver and string argument
    (call
        receiver: (identifier) @key
        method: (identifier)
        arguments: (argument_list
            (string
                (string_content) @val
            )
        )
    )
    
    ; Assignment with method call and two string arguments
    (assignment
        left: (identifier)
        right: (call
            arguments: (argument_list
                (string
                    (string_content) @key
                )
                (string
                    (string_content) @val
                )
            )
        )
    )
    
    ; Method call with receiver and two string arguments
    (call
        receiver: (identifier)
        method: (identifier)
        arguments: (argument_list
            (string
                (string_content) @key
            )
            (string
                (string_content) @val
            )
        )
    )
    
    ; Method call with string argument
    (call
        method: (identifier) @key
        arguments: (argument_list
            (string) @val
        )
    )
    
    ; Assignment with string array
    (assignment
        left: (identifier) @key
        right: (string_array
            (bare_string
                (string_content) @val
            )
        )
    )
"#;
pub const QUERIES_GO: &str = r#"
    ; Query 1: Matches variable declarations with string literal values
    (var_spec
        name: (identifier) @key
        value: (expression_list
            (interpreted_string_literal) @val
        )
    )

    ; Query 2: Matches short variable declarations with string literal values
    (short_var_declaration
        left: (expression_list
            (identifier) @key
        )
        right: (expression_list
            (interpreted_string_literal) @val
        )
    )

    ; Query 3: Matches assignment statements with string literal values
    (assignment_statement
        left: (expression_list
            (identifier) @key
        )
        right: (expression_list
            (interpreted_string_literal) @val
        )
    )

    ; Query 4: Matches short variable declarations with selector expressions and string literal values
    (short_var_declaration
        left: (expression_list
            (selector_expression
                field: (field_identifier) @key
            )
        )
        right: (expression_list
            (interpreted_string_literal) @val
        )
    )

    ; Query 5: Matches assignment statements with selector expressions and string literal values
    (assignment_statement
        left: (expression_list
            (selector_expression) @key
        )
        right: (expression_list
            (interpreted_string_literal) @val
        )
    )

    ; Query 6: Matches variable specifications with optional type and string literal values
    (var_spec
        (identifier) @key
        (type_identifier)?
        "="
        (expression_list
          (interpreted_string_literal) @val
        )+
    )
"#;
pub const QUERIES_HTML: &str = r#"
    ; Query 1: Matches HTML elements with text content
    (element
        (start_tag (tag_name) @key)
        (text) @val
    )

    ; Query 2: Matches HTML attributes with quoted values
    (attribute
        (attribute_name) @key
        (quoted_attribute_value
            (attribute_value) @value
        )
    )

    ; Query 3: Extracts embedded JavaScript from script tags
    (script_element
        (start_tag) @key
        (raw_text) @val
    )
"#;
pub const QUERIES_JAVA: &str = r#"
    ; Query 1: Matches variable declarations with cast expressions
    declarator: (variable_declarator
        name: (identifier) @key
        value: (parenthesized_expression
            (cast_expression
                value: [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
            )
        )
    )

    ; Query 2: Matches variable declarations with object creation or literal values
    declarator: (variable_declarator
        name: (identifier) @key
        value: [(object_creation_expression
            arguments: (argument_list
                [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
            )
        )[(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val]
    )

    ; Query 3: Matches variable declarations with method invocations
    declarator: (variable_declarator
        name: (identifier) @key
        value: (method_invocation
            arguments: (argument_list
                [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
            )
        )
    )

    ; Query 4: Matches variable declarations with lambda expressions
    declarator: (variable_declarator
        name: (identifier) @key
        value: (lambda_expression
            body: (
                    (_
                        object: (string_literal) @val
                    )
            )
        )
    )

    ; Query 5: Matches assignment expressions with object creation
    (assignment_expression
        left: (identifier) @key
        right: (object_creation_expression
            arguments: (argument_list
                [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
            )
        )
    )

    ; Query 6: Matches assignment expressions with field access
    (assignment_expression
        left: (field_access
            field: (identifier) @key
        )
        right: [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
    )

    ; Query 7: Matches simple assignment expressions
    (assignment_expression
        left: (identifier) @key
        right: [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
    )

    ; Query 8: Matches field declarations
    (field_declaration
        declarator: (variable_declarator
            name: (identifier) @key
            value: [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
        )
    )

    ; Query 9: Matches element value pairs in annotations
    (element_value_pair
        key: (identifier) @key
        value: [(string_literal)(decimal_integer_literal)(decimal_floating_point_literal)(hex_integer_literal)(hex_floating_point_literal)(binary_integer_literal)] @val
    )

    ; Query 10: Matches method arguments with field access and string literals
    arguments: (argument_list
        (field_access
            field: (identifier) @key
        )
        (string_literal) @val
    )

    ; Query 11: Matches local variable declarations with string literals
    (local_variable_declaration
        declarator: (_
            name: (identifier) @key
            value: (_
                (string_literal
                    (string_fragment) @val
                )
            )
        )
    )

    ; Query 12: Matches nested local variable declarations with string literals
    (local_variable_declaration
        declarator: (_
            name: (identifier) @key
            value: (_
              value: (_
                  (string_literal
                      (string_fragment) @val
                  )
              )
            )
        )
    )

    ; Query 13: Matches method invocations with string literal arguments
    (expression_statement
        (method_invocation
            name: (identifier) @key
            arguments: (_
                (string_literal
                    (string_fragment) @val
                )
            )
        )
    )
"#;
pub const QUERIES_JAVASCRIPT: &str = r#"
   ; Query 1: Matches assignments to object properties
    (assignment_expression
        left: (member_expression
            property: (property_identifier) @key
        )
        right: (string (string_fragment) @val)
    )

    ; Query 2: Matches variable declarations with literal values
    (variable_declarator
        name: (identifier) @key
        value: (string (string_fragment) @val)
    )

    ; Query 3: Matches variable declarations with object literals
    (variable_declarator
        name: (identifier)
        value: (object
            (pair
                key: (property_identifier) @key
                value: (string (string_fragment) @val)
            )
        )
    )

    ; Query 4: Matches function calls with identifier and string arguments
    (call_expression
        arguments: (arguments
            (identifier) @key
            (string (string_fragment) @val)
        )
    )

    ; Query 5: Matches object literal key-value pairs
    (pair
        key: (property_identifier) @key
        value: (string (string_fragment) @val)
    )

    ; Query 6: Matches assignments to array or object elements
    (assignment_expression
        left: (subscript_expression
            index: [(string)(identifier)] @key
        )
        right: (string (string_fragment) @val)
    )

    ; Query 7: Matches method calls on objects with string arguments
    (call_expression
        function: (member_expression
            object: (identifier) @key
        )
        arguments: (arguments
            (string
                (string_fragment) @val
            )
        )
    )
"#;
pub const QUERIES_KOTLIN: &str = r#"
    ; Query 1: Matches property declarations with string literals
    (property_declaration
        (variable_declaration
            (simple_identifier) @key
        ) 
        (string_literal) @val
    )

    ; Query 2: Matches property declarations with call expressions and string literals
    (property_declaration
        (variable_declaration
            (simple_identifier) @key
        ) 
        (call_expression
            (navigation_expression
                (string_literal) @val
            )
        )
    )

    ; Query 3: Matches property declarations with call expressions and value arguments
    (property_declaration
        (variable_declaration
            (simple_identifier) @key
        ) 
        (call_expression
            (call_suffix
                (value_arguments
                    (value_argument) @val
                )
            )
        )
    )

    ; Query 4: Matches assignments with string literals
    (assignment
        (directly_assignable_expression
            (simple_identifier) @key
        )
        (string_literal) @val
    )

    ; Query 5: Matches property declarations with property delegates and string literals
    (property_declaration
        (variable_declaration
            (simple_identifier) @key
        ) 
        (property_delegate
            (_
                (call_suffix
                    (_
                        (_
                            (_
                                (string_literal) @val
                            )
                        )
                    )
                )
            )
        )
    )

    ; Query 6: Matches secondary constructor assignments with string literals
    (secondary_constructor
        (statements
            (assignment
                (directly_assignable_expression
                    (navigation_suffix
                        (simple_identifier) @key
                    )
                )
                (string_literal) @val
            )
        )
    )
"#;
pub const QUERIES_PHP: &str = r#"
    ; Query 1: Matches variable assignments
    (expression_statement
        (assignment_expression
            left: (variable_name
                (name) @key
            )
            right: [(string)(integer)] @val
        )
    )

    ; Query 2: Matches property declarations with initializers
    (property_declaration
        (property_element
            (variable_name
                (name) @key
            )
            default_value: (string
            	(string_content) @val	
            )
        )
    )

    ; Query 3: Matches assignments to object properties
    (expression_statement
        (assignment_expression
            left: (member_access_expression
                (name) @key
            )
            right: [(string)(integer)] @val
        )
    )


    ; Query 4: Matches method calls with string or integer arguments
    (expression_statement
        (member_call_expression
            name: (name) @key
            arguments: (arguments
                (argument
                	[(string)(integer)] @val
                )
            )
        )
    )
    
    ; Query 5
    (expression_statement
    	(variable_name) @key
        (_
        	(name) @val
        )
    )
    
    ; Query 6
    (assignment_expression
    	left: (variable_name
        	(name) @key
        )
        right: (encapsed_string
        	(string_content) @val
        )
    )
    
    ; Query 7
    (assignment_expression
    	left: (member_access_expression
        	name: (name) @key
        )
        right: (encapsed_string
        	(string_content) @val
        )
    )
"#;
pub const QUERIES_PYTHON: &str = r#"
    ; Query 1: Matches assignments to object attributes
    (assignment
        left: (attribute
            attribute: (identifier) @key
        )
        right: [(string)(integer)] @val
    )

    ; Query 2: Matches dictionary key-value pairs
    (pair
        key: (string) @key
        value: [(string)(integer)(attribute)] @val
    )

    ; Query 3: Matches function calls with keyword arguments
    (call
        arguments: (argument_list
            (keyword_argument
                name: (identifier) @key
                value: (string) @val
            )
        )
    )

    ; Query 4: Matches function calls with keyword arguments containing tuples, lists, or attributes
    (call
        arguments: (argument_list
            (keyword_argument
                name: (identifier) @key
                value: [
                        (tuple(attribute) @val)
                        (list(string) @val)
                        ]
            )
        )
    )

    ; Query 5: Matches assignments with function calls containing string or integer arguments
    (expression_statement
        (assignment
            left: (_) @key
            right: (expression_list
                (call
                    arguments: (argument_list
                        [(string)(integer)] @val
                    )
                ) 
            )
        )
    )

    ; Query 6: Matches assignments with dictionary values
    (expression_statement
        (assignment
            left: (_) @key
            right: (expression_list
                (dictionary
                    (pair) @val
                )
            )
        )
    )

    ; Query 7: Matches function calls with keyword arguments containing lists of strings
    (call
        arguments: (argument_list
            (keyword_argument
                name: (identifier) @key
                value: (list
                    (string) @val
                )
            )
        )
    )

    ; Query 8: Matches function calls with keyword arguments containing dictionaries
    (call
        arguments: (argument_list
            (keyword_argument
                name: (identifier) @key
                value: (dictionary
                    (pair) @val
                )
            )
        )
    )

    ; Query 9: Matches function calls with keyword arguments containing tuples
    (call
        arguments: (argument_list
            (keyword_argument
                name: (identifier) @key
                value: (tuple
                    (_) @val
                )
            )
        )
    )

    ; Query 10: Matches simple variable assignments
    (assignment
        left: (identifier) @key
        right: [(string)(integer)] @val
    )

    ; Query 11: Matches assignments with function calls containing string arguments
    (assignment
        left: (identifier) @key
        right: (call
            arguments: (argument_list
                (string) @val
            )
        )
    )

    ; Query 12: Matches assignments with method calls containing string arguments
    (assignment
        right: (call
            function: (attribute) @key
            arguments: (argument_list
                (string) @val
            )
        )
    )

    ; Query 13: Matches string arguments in function calls
    (call
        function: (attribute) @key
        arguments: (argument_list
            (string
                (string_content) @val
            )
        )
    )
"#;
pub const QUERIES_TOML: &str = r#"
    ; Query 1: Matches key-value pairs
    (pair
        [(bare_key)(string)] @key
        [(bare_key)(string)] @val
    )

    ; Query 2: Matches key-value pairs with array values containing strings
    (pair
        [(bare_key)(string)] @key
        (array
            (string) @val
        )
    )

    ; Query 3: Matches key-value pairs with nested array values containing strings
    (pair
        [(bare_key)(string)] @key
        (array
            (array
                (string) @val
            )
        )
    )
"#;
pub const QUERIES_TYPESCRIPT: &str = r#"
    ; Query 1: Matches variable declarations with string or number values
    (variable_declarator
        name: (identifier) @key
        value: [(string)(number)] @val
    )

    ; Query 2: Matches assignments to variables or object properties
    (assignment_expression
        left: [(member_expression)(identifier)] @key
        right: [(string)(number)] @val
    )

    ; Query 3: Matches variable declarations with string literal type annotations
    (variable_declarator
        name: (identifier) @key
        type: (type_annotation
            (literal_type
                (string) @val
            )
        )
    )

    ; Query 4: Matches object property definitions with array values containing strings
    (pair
        key: (property_identifier) @key
        value: (
            (array
                (string) @val
            )
        )
    )

    ; Query 5: Matches object property definitions with string or number values
    (pair
        key: (property_identifier) @key
        value: [(string)(number)] @val
    )

    ; Query 6: Matches property signatures with literal types
    (property_signature
        name: (property_identifier) @key
        (_ 
            (literal_type) @val
        )
    )

    ; Query 7: Matches property signatures with union types
    (property_signature
        name: (property_identifier) @key
        type: (type_annotation
            (union_type) @val
        )
    )

    ; Query 8: Matches method calls with string arguments
    (call_expression
        function: (_ 
            property: (property_identifier) @key
        )
        arguments: (arguments
            (string) @val
        )
    )
"#;
