<?php                     
/** 
 * Plugin Name: Gumroad Connect
 * Plugin URI: https://github.com/sinanisler/gumroad-connect
 * Description: Connect your WordPress site with Gumroad to automatically create user accounts when customers make a purchase.
 * Version: 1.25
 * Author: sinanisler
 * Author URI: https://sinanisler.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: gumroad-connect
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Include GitHub auto-update functionality
require_once plugin_dir_path(__FILE__) . 'include/github-update.php';

class Gumroad_Connect {
    
    private $option_name = 'gumroad_connect_settings';
    private $ping_log_option = 'gumroad_connect_ping_log';
    private $user_log_option = 'gumroad_connect_user_log';
    private $products_option = 'gumroad_connect_products';
    
    public function __construct() {
        // Plugin activation
        register_activation_hook(__FILE__, array($this, 'activate_plugin'));
        
        // Admin menu
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // REST API endpoint
        add_action('rest_api_init', array($this, 'register_rest_route'));
        
        // Admin styles
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
    }
    
    /**
     * Activate plugin - Generate endpoint hash
     */
    public function activate_plugin() {
        // Generate unique endpoint hash if not exists
        if (!get_option('gumroad_connect_endpoint_hash')) {
            $this->generate_endpoint_hash();
        }
    }
    
    /**
     * Generate unique endpoint hash based on domain
     */
    private function generate_endpoint_hash() {
        $domain = get_site_url();
        $salt = wp_generate_password(32, true, true);
        $hash = substr(md5($domain . $salt . time()), 0, 16);
        update_option('gumroad_connect_endpoint_hash', $hash);
        return $hash;
    }
    
    /**
     * Get endpoint hash
     */
    private function get_endpoint_hash() {
        $hash = get_option('gumroad_connect_endpoint_hash');
        if (!$hash) {
            $hash = $this->generate_endpoint_hash();
        }
        return $hash;
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_menu_page(
            'Gumroad Connect',
            'Gumroad Connect',
            'manage_options',
            'gumroad-connect',
            array($this, 'settings_page'),
            'dashicons-cart',
            100
        );
        
        add_submenu_page(
            'gumroad-connect',
            'Settings',
            'Settings',
            'manage_options',
            'gumroad-connect',
            array($this, 'settings_page')
        );
        
        add_submenu_page(
            'gumroad-connect',
            'Ping Test',
            'Ping Test',
            'manage_options',
            'gumroad-connect-test',
            array($this, 'test_page')
        );
        
        add_submenu_page(
            'gumroad-connect',
            'User Log',
            'User Log',
            'manage_options',
            'gumroad-connect-users',
            array($this, 'user_log_page')
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting(
            'gumroad_connect_settings_group',
            $this->option_name,
            array(
                'sanitize_callback' => array($this, 'sanitize_settings'),
                'type' => 'array',
            )
        );
    }
    
    /**
     * Sanitize settings
     */
    public function sanitize_settings($input) {
        $sanitized = array();
        
        if (isset($input['seller_id'])) {
            $sanitized['seller_id'] = sanitize_text_field($input['seller_id']);
        }
        
        if (isset($input['create_users'])) {
            $sanitized['create_users'] = (bool) $input['create_users'];
        }
        
        // Always set user_roles, even if empty (to allow unchecking all roles)
        if (isset($input['user_roles']) && is_array($input['user_roles'])) {
            $sanitized['user_roles'] = array_map('sanitize_text_field', $input['user_roles']);
        } else {
            $sanitized['user_roles'] = array(); // Empty array if no roles selected
        }
        
        if (isset($input['email_subject'])) {
            $sanitized['email_subject'] = sanitize_text_field($input['email_subject']);
        }
        
        if (isset($input['email_message'])) {
            // Allow full HTML - strip slashes to prevent accumulation on each save
            $sanitized['email_message'] = wp_unslash($input['email_message']);
        }
        
        // Always set product_roles, even if empty
        if (isset($input['product_roles']) && is_array($input['product_roles'])) {
            $sanitized['product_roles'] = array();
            foreach ($input['product_roles'] as $product_id => $roles) {
                if (is_array($roles)) {
                    $sanitized['product_roles'][sanitize_text_field($product_id)] = array_map('sanitize_text_field', $roles);
                }
            }
        } else {
            $sanitized['product_roles'] = array(); // Empty array if no product roles configured
        }
        
        // Sanitize log limit settings (storage limits)
        if (isset($input['ping_log_limit'])) {
            $ping_log_limit = intval($input['ping_log_limit']);
            $sanitized['ping_log_limit'] = max(10, min(1000, $ping_log_limit)); // Between 10 and 1000
        }
        
        if (isset($input['user_log_limit'])) {
            $user_log_limit = intval($input['user_log_limit']);
            $sanitized['user_log_limit'] = max(10, min(1000, $user_log_limit)); // Between 10 and 1000
        }
        
        // Sanitize per-page display settings
        if (isset($input['ping_per_page'])) {
            $ping_per_page = intval($input['ping_per_page']);
            $sanitized['ping_per_page'] = max(10, min(200, $ping_per_page)); // Between 10 and 200
        }
        
        if (isset($input['user_per_page'])) {
            $user_per_page = intval($input['user_per_page']);
            $sanitized['user_per_page'] = max(10, min(200, $user_per_page)); // Between 10 and 200
        }
        
        return $sanitized;
    }
    
    /**
     * Register REST API route
     */
    public function register_rest_route() {
        $endpoint_hash = $this->get_endpoint_hash();
        
        register_rest_route('gumroad-connect/v1', '/ping/' . $endpoint_hash, array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_ping'),
            'permission_callback' => '__return_true', // Public endpoint
        ));
    }
    
    /**
     * Handle incoming Gumroad ping
     */
    public function handle_ping($request) {
        // Get all parameters
        $params = $request->get_params();
        
        // Get stored settings
        $settings = get_option($this->option_name, array());
        $stored_seller_id = isset($settings['seller_id']) ? $settings['seller_id'] : '';
        $create_users = isset($settings['create_users']) ? $settings['create_users'] : true;
        
        // Verify seller_id if configured
        $seller_id_match = false;
        if (!empty($stored_seller_id) && isset($params['seller_id'])) {
            $seller_id_match = ($params['seller_id'] === $stored_seller_id);
        }
        
        // Prepare log entry
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'datetime_readable' => current_time('Y-m-d H:i:s'),
            'seller_id_match' => $seller_id_match,
            'stored_seller_id' => $stored_seller_id,
            'data' => $params,
            'headers' => $this->get_request_headers($request),
        );
        
        // Store in ping log with dynamic limit (automatic cleanup)
        $ping_log_limit = isset($settings['ping_log_limit']) ? intval($settings['ping_log_limit']) : 100;
        $ping_log = get_option($this->ping_log_option, array());
        array_unshift($ping_log, $log_entry);
        $ping_log = array_slice($ping_log, 0, $ping_log_limit); // Auto-delete oldest entries
        update_option($this->ping_log_option, $ping_log);
        
        // Store product information for selection in settings
        if (isset($params['short_product_id']) && isset($params['product_name'])) {
            $this->store_product_info($params['short_product_id'], $params['product_name']);
        }
        
        // Process user creation/update/cancellation if enabled and verified
        $user_creation_result = null;
        if ($create_users && $seller_id_match && isset($params['email'])) {
            // Check if this is a refund or cancellation
            $is_refunded = isset($params['refunded']) && $params['refunded'] === 'true';
            $is_recurring = isset($params['is_recurring_charge']) && $params['is_recurring_charge'] === 'true';
            $has_subscription_id = isset($params['subscription_id']) && !empty($params['subscription_id']);
            
            // Handle subscription cancellation or refund
            if ($is_refunded && $has_subscription_id) {
                $user_creation_result = $this->handle_subscription_cancellation($params);
            } else {
                // Check if product-specific roles are configured
                $product_roles = isset($settings['product_roles']) ? $settings['product_roles'] : array();
                $short_product_id = isset($params['short_product_id']) ? $params['short_product_id'] : '';
                
                // If no product roles configured, use default roles from settings (backward compatibility)
                // If product roles exist, only create users for configured products
                if (empty($product_roles) || isset($product_roles[$short_product_id])) {
                    $user_creation_result = $this->create_or_update_user($params);
                } else {
                    $user_creation_result = array(
                        'status' => 'skipped',
                        'message' => 'Product not configured for user creation',
                        'product_id' => $short_product_id,
                    );
                }
            }
        }
        
        // Return success response
        return new WP_REST_Response(array(
            'success' => true,
            'message' => 'Ping received successfully',
            'timestamp' => current_time('mysql'),
            'seller_id_verified' => $seller_id_match,
            'user_created' => $user_creation_result,
        ), 200);
    }
    
    /**
     * Handle subscription cancellation or refund
     */
    private function handle_subscription_cancellation($params) {
        $email = sanitize_email($params['email']);
        $subscription_id = isset($params['subscription_id']) ? $params['subscription_id'] : '';
        $product_name = isset($params['product_name']) ? $params['product_name'] : 'Product';
        $short_product_id = isset($params['short_product_id']) ? $params['short_product_id'] : '';
        
        $result = array(
            'status' => 'error',
            'message' => '',
            'user_id' => 0,
            'email' => $email,
            'action' => 'cancellation',
        );
        
        // Find user by email
        $user = get_user_by('email', $email);
        
        if (!$user) {
            $result['message'] = 'User not found with email: ' . $email;
            $this->log_user_action($result, $params);
            return $result;
        }
        
        $user_id = $user->ID;
        
        // Verify subscription ID matches
        $stored_subscription_id = get_user_meta($user_id, 'gumroad_subscription_id', true);
        if ($stored_subscription_id !== $subscription_id) {
            $result['message'] = 'Subscription ID mismatch. Stored: ' . $stored_subscription_id . ', Received: ' . $subscription_id;
            $result['user_id'] = $user_id;
            $this->log_user_action($result, $params);
            return $result;
        }
        
        // Get the roles that were assigned for this product
        $settings = get_option($this->option_name, array());
        $product_roles = isset($settings['product_roles']) ? $settings['product_roles'] : array();
        
        // Determine which roles to remove
        $roles_to_remove = array();
        if (!empty($short_product_id) && isset($product_roles[$short_product_id]) && !empty($product_roles[$short_product_id])) {
            $roles_to_remove = $product_roles[$short_product_id];
        } else {
            // Fall back to default user_roles setting
            $roles_to_remove = isset($settings['user_roles']) ? $settings['user_roles'] : array('subscriber');
        }
        
        // Remove roles from user
        $roles_removed = array();
        foreach ($roles_to_remove as $role) {
            if (in_array($role, $user->roles)) {
                $user->remove_role($role);
                $roles_removed[] = $role;
            }
        }
        
        // Update subscription status
        update_user_meta($user_id, 'gumroad_subscription_status', 'cancelled');
        update_user_meta($user_id, 'gumroad_subscription_cancelled_date', current_time('mysql'));
        
        $result['status'] = 'cancelled';
        $result['message'] = 'Subscription cancelled. Roles removed: ' . implode(', ', $roles_removed);
        $result['user_id'] = $user_id;
        $result['roles_removed'] = $roles_removed;
        $result['subscription_id'] = $subscription_id;
        
        // Log the cancellation
        $this->log_user_action($result, $params);
        
        return $result;
    }
    
    /**
     * Store product information from ping
     */
    private function store_product_info($short_product_id, $product_name) {
        $products = get_option($this->products_option, array());
        
        // Store or update product info with short_product_id as key
        if (!isset($products[$short_product_id])) {
            $products[$short_product_id] = array(
                'name' => $product_name,
                'first_seen' => current_time('mysql'),
                'last_seen' => current_time('mysql'),
            );
        } else {
            // Update product name and last seen time
            $products[$short_product_id]['name'] = $product_name;
            $products[$short_product_id]['last_seen'] = current_time('mysql');
        }
        
        update_option($this->products_option, $products);
    }
    
    /**
     * Create or update user from Gumroad purchase
     */
    private function create_or_update_user($params) {
        $email = sanitize_email($params['email']);
        $product_name = isset($params['product_name']) ? $params['product_name'] : 'Product';
        $sale_id = isset($params['sale_id']) ? $params['sale_id'] : '';
        $full_name = isset($params['full_name']) ? $params['full_name'] : '';
        
        // Check if user already exists
        $user = get_user_by('email', $email);
        
        $settings = get_option($this->option_name, array());
        $short_product_id = isset($params['short_product_id']) ? $params['short_product_id'] : '';
        
        // Check if product-specific roles are configured
        $product_roles = isset($settings['product_roles']) ? $settings['product_roles'] : array();
        
        // Use product-specific roles if configured, otherwise fall back to default user_roles setting
        if (!empty($short_product_id) && isset($product_roles[$short_product_id]) && !empty($product_roles[$short_product_id])) {
            $user_roles = $product_roles[$short_product_id];
        } else {
            $user_roles = isset($settings['user_roles']) ? $settings['user_roles'] : array('subscriber');
        }
        
        $result = array(
            'status' => 'error',
            'message' => '',
            'user_id' => 0,
            'email' => $email,
            'password_sent' => false,
        );
        
        if ($user) {
            // User exists - add roles if needed
            $user_id = $user->ID;
            $roles_added = array();
            
            foreach ($user_roles as $role) {
                if (!in_array($role, $user->roles)) {
                    $user->add_role($role);
                    $roles_added[] = $role;
                }
            }
            
            // Update subscription info if this is a subscription
            $subscription_id = isset($params['subscription_id']) ? $params['subscription_id'] : '';
            $is_recurring = isset($params['is_recurring_charge']) ? $params['is_recurring_charge'] : 'false';
            $recurrence = isset($params['recurrence']) ? $params['recurrence'] : '';
            
            if (!empty($subscription_id)) {
                update_user_meta($user_id, 'gumroad_subscription_id', $subscription_id);
                update_user_meta($user_id, 'gumroad_is_recurring', $is_recurring);
                update_user_meta($user_id, 'gumroad_recurrence', $recurrence);
                update_user_meta($user_id, 'gumroad_subscription_status', 'active');
                update_user_meta($user_id, 'gumroad_last_payment', current_time('mysql'));
            }
            
            $result['status'] = 'existing';
            $result['message'] = 'User already exists. Roles updated: ' . implode(', ', $roles_added);
            $result['user_id'] = $user_id;
            $result['roles_added'] = $roles_added;
            
        } else {
            // Create new user
            $username = $this->generate_username($email, $full_name);
            $password = wp_generate_password(12, true, false);
            
            $user_data = array(
                'user_login' => $username,
                'user_email' => $email,
                'user_pass' => $password,
                'role' => 'subscriber', // Default role
            );
            
            // Add full name if available
            if (!empty($full_name)) {
                $name_parts = explode(' ', $full_name, 2);
                $user_data['first_name'] = $name_parts[0];
                if (isset($name_parts[1])) {
                    $user_data['last_name'] = $name_parts[1];
                }
                $user_data['display_name'] = $full_name;
            }
            
            $user_id = wp_insert_user($user_data);
            
            if (is_wp_error($user_id)) {
                $result['status'] = 'error';
                $result['message'] = $user_id->get_error_message();
            } else {
                // Add custom roles
                $user = new WP_User($user_id);
                foreach ($user_roles as $role) {
                    $user->add_role($role);
                }
                
                // Add Gumroad metadata
                update_user_meta($user_id, 'gumroad_sale_id', $sale_id);
                update_user_meta($user_id, 'gumroad_product_name', $product_name);
                update_user_meta($user_id, 'gumroad_purchase_date', current_time('mysql'));
                
                // Store subscription info if this is a subscription
                $subscription_id = isset($params['subscription_id']) ? $params['subscription_id'] : '';
                $is_recurring = isset($params['is_recurring_charge']) ? $params['is_recurring_charge'] : 'false';
                $recurrence = isset($params['recurrence']) ? $params['recurrence'] : '';
                
                if (!empty($subscription_id)) {
                    update_user_meta($user_id, 'gumroad_subscription_id', $subscription_id);
                    update_user_meta($user_id, 'gumroad_is_recurring', $is_recurring);
                    update_user_meta($user_id, 'gumroad_recurrence', $recurrence);
                    update_user_meta($user_id, 'gumroad_subscription_status', 'active');
                    update_user_meta($user_id, 'gumroad_subscription_start', current_time('mysql'));
                }
                
                // Send welcome email with credentials
                $email_sent = $this->send_welcome_email($user_id, $email, $username, $password, $product_name);
                
                $result['status'] = 'created';
                $result['message'] = 'User created successfully';
                $result['user_id'] = $user_id;
                $result['username'] = $username;
                $result['password_sent'] = $email_sent;
                $result['roles'] = $user_roles;
            }
        }
        
        // Log user creation/update
        $this->log_user_action($result, $params);
        
        return $result;
    }
    
    /**
     * Generate unique username
     */
    private function generate_username($email, $full_name = '') {
        // Try full name first
        if (!empty($full_name)) {
            $username = sanitize_user(str_replace(' ', '', strtolower($full_name)));
            if (!username_exists($username)) {
                return $username;
            }
        }
        
        // Use email prefix
        $username = sanitize_user(strtolower(substr($email, 0, strpos($email, '@'))));
        
        // If username exists, add numbers
        $base_username = $username;
        $counter = 1;
        while (username_exists($username)) {
            $username = $base_username . $counter;
            $counter++;
        }
        
        return $username;
    }
    
    /**
     * Send welcome email to new user
     */
    private function send_welcome_email($user_id, $email, $username, $password, $product_name) {
        $settings = get_option($this->option_name, array());
        
        // Get custom email content or use default
        $subject = isset($settings['email_subject']) && !empty($settings['email_subject']) 
            ? $settings['email_subject'] 
            : 'Welcome! Your Account Has Been Created';
        
        $custom_message = isset($settings['email_message']) && !empty($settings['email_message']) 
            ? $settings['email_message'] 
            : '';
        
        // Build email content
        $login_url = wp_login_url();
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();
        
        // Generate password reset link
        $reset_key = get_password_reset_key(new WP_User($user_id));
        $password_reset_url = '';
        if (!is_wp_error($reset_key)) {
            $password_reset_url = network_site_url("wp-login.php?action=rp&key=$reset_key&login=" . rawurlencode($username), 'login');
        }
        
        // Default email template
        $default_template = $this->get_default_email_template();
        
        // Use custom message or default template
        $message = !empty($custom_message) ? $custom_message : $default_template;
        
        // Replace dynamic tags
        $message = $this->replace_email_tags($message, array(
            'site_name' => $site_name,
            'site_url' => $site_url,
            'product_name' => $product_name,
            'username' => $username,
            'password' => $password,
            'email' => $email,
            'login_url' => $login_url,
            'password_reset_url' => $password_reset_url,
        ));
        
        // Replace subject tags
        $subject = $this->replace_email_tags($subject, array(
            'site_name' => $site_name,
            'product_name' => $product_name,
            'username' => $username,
        ));
        
        // Send email as HTML
        $headers = array('Content-Type: text/html; charset=UTF-8');
        return wp_mail($email, $subject, $message, $headers);
    }
    
    /**
     * Get default email template
     */
    private function get_default_email_template() {
        return '<p>Hi there!</p>

<p>Thank you for your purchase of <strong>{{product_name}}</strong>!</p>

<p>Your account has been created on <strong>{{site_name}}</strong>.</p>

<h3>Your Login Credentials:</h3>
<ul>
    <li><strong>Username:</strong> {{username}}</li>
    <li><strong>Password:</strong> {{password}}</li>
    <li><strong>Login URL:</strong> <a href="{{login_url}}">{{login_url}}</a></li>
</ul>

<p>We recommend changing your password after your first login.</p>

<p>Alternatively, you can <a href="{{password_reset_url}}">reset your password here</a>.</p>

<p>Best regards,<br>
{{site_name}} Team</p>';
    }
    
    /**
     * Replace email dynamic tags
     */
    private function replace_email_tags($content, $tags) {
        foreach ($tags as $key => $value) {
            $content = str_replace('{{' . $key . '}}', $value, $content);
        }
        return $content;
    }
    
    /**
     * Log user action
     */
    private function log_user_action($result, $gumroad_data) {
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'datetime_readable' => current_time('Y-m-d H:i:s'),
            'result' => $result,
            'gumroad_data' => array(
                'sale_id' => isset($gumroad_data['sale_id']) ? $gumroad_data['sale_id'] : '',
                'product_name' => isset($gumroad_data['product_name']) ? $gumroad_data['product_name'] : '',
                'email' => isset($gumroad_data['email']) ? $gumroad_data['email'] : '',
                'price' => isset($gumroad_data['price']) ? $gumroad_data['price'] : '',
                'test' => isset($gumroad_data['test']) ? $gumroad_data['test'] : 'false',
            ),
        );
        
        // Store in user log with dynamic limit (automatic cleanup)
        $settings = get_option($this->option_name, array());
        $user_log_limit = isset($settings['user_log_limit']) ? intval($settings['user_log_limit']) : 100;
        $user_log = get_option($this->user_log_option, array());
        array_unshift($user_log, $log_entry);
        $user_log = array_slice($user_log, 0, $user_log_limit); // Auto-delete oldest entries
        update_option($this->user_log_option, $user_log);
    }
    
    /**
     * Get request headers
     */
    private function get_request_headers($request) {
        $headers = array();
        foreach ($request->get_headers() as $key => $value) {
            $headers[$key] = is_array($value) ? implode(', ', $value) : $value;
        }
        return $headers;
    }
    
    /**
     * Settings page
     */
    public function settings_page() {
        // Handle settings save
        if (isset($_POST['save_gumroad_settings']) && isset($_POST['gumroad_save_settings_nonce']) && wp_verify_nonce($_POST['gumroad_save_settings_nonce'], 'gumroad_save_settings')) {
            if (isset($_POST[$this->option_name])) {
                $sanitized = $this->sanitize_settings($_POST[$this->option_name]);
                update_option($this->option_name, $sanitized);
                echo '<div class="notice notice-success is-dismissible"><p><strong>✅ Settings saved successfully!</strong></p></div>';
            }
        }
        
        // Handle product deletion
        if (isset($_POST['delete_product']) && isset($_POST['product_id']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'gumroad_delete_product')) {
            $product_id = sanitize_text_field($_POST['product_id']);
            $products = get_option($this->products_option, array());
            
            if (isset($products[$product_id])) {
                $product_name = $products[$product_id]['name'];
                unset($products[$product_id]);
                update_option($this->products_option, $products);
                
                // Also remove product roles configuration if exists
                $settings = get_option($this->option_name, array());
                if (isset($settings['product_roles'][$product_id])) {
                    unset($settings['product_roles'][$product_id]);
                    update_option($this->option_name, $settings);
                }
                
                echo '<div class="notice notice-success"><p><strong>✅ Product deleted successfully!</strong> "' . esc_html($product_name) . '" has been removed.</p></div>';
            }
        }
        
        // Handle hash refresh action
        if (isset($_POST['refresh_endpoint_hash']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'gumroad_refresh_hash')) {
            $this->generate_endpoint_hash();
            echo '<div class="notice notice-success"><p><strong>✅ Endpoint hash refreshed successfully!</strong> Make sure to update your Gumroad webhook URL with the new endpoint.</p></div>';
        }
        
        $settings = get_option($this->option_name, array());
        $seller_id = isset($settings['seller_id']) ? $settings['seller_id'] : '';
        $create_users = isset($settings['create_users']) ? $settings['create_users'] : true;
        $user_roles = isset($settings['user_roles']) ? $settings['user_roles'] : array('paidmember', 'subscriber');
        $email_subject = isset($settings['email_subject']) ? $settings['email_subject'] : 'Welcome! Your Account Has Been Created';
        $email_message = isset($settings['email_message']) ? $settings['email_message'] : '';
        $product_roles = isset($settings['product_roles']) ? $settings['product_roles'] : array();
        
        // Get the REST endpoint URL with unique hash
        $endpoint_hash = $this->get_endpoint_hash();
        $endpoint_url = rest_url('gumroad-connect/v1/ping/' . $endpoint_hash);
        
        // Get all available roles
        $wp_roles = wp_roles();
        $available_roles = $wp_roles->get_names();
        
        // Get stored products from pings
        $stored_products = get_option($this->products_option, array());
        
        ?>
        <div class="wrap gumroad-connect-wrap">
            <h1>🛒 Gumroad Connect - Settings</h1>
            
            <div class="gumroad-connect-container">
                
                <!-- Settings Card -->
                <div class="gumroad-card">
                    <h2>⚙️ Configuration</h2>
                    <form method="post" action="">
                        <?php wp_nonce_field('gumroad_save_settings', 'gumroad_save_settings_nonce'); ?>
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <label for="seller_id">Seller ID</label>
                                </th>
                                <td>
                                    <input 
                                        type="text" 
                                        id="seller_id" 
                                        name="<?php echo esc_attr($this->option_name); ?>[seller_id]" 
                                        value="<?php echo esc_attr($seller_id); ?>" 
                                        class="regular-text"
                                        placeholder="RcuODgh_........"
                                        style="width:100px"
                                    />
                                    <p class="description">
                                        Your Gumroad seller ID. This will be verified against incoming pings for security.
                                        <br> Find your seller id in same place under the 
                                        <a href="https://gumroad.com/settings/advanced" target="_blank">ping input setting</a>.
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label for="create_users">Auto Create Users</label>
                                </th>
                                <td>
                                    <label>
                                        <input 
                                            type="checkbox" 
                                            id="create_users" 
                                            name="<?php echo esc_attr($this->option_name); ?>[create_users]" 
                                            value="1"
                                            <?php checked($create_users, true); ?>
                                        />
                                        Automatically create WordPress users for Gumroad purchases
                                    </label>
                                    <p class="description">
                                        When enabled, a new WordPress user will be created for each purchase.
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label>Assign User Roles</label>
                                </th>
                                <td>
                                    <fieldset>
                                        <?php foreach ($available_roles as $role_key => $role_name): ?>
                                            <label style="display: block; margin-bottom: 8px;">
                                                <input 
                                                    type="checkbox" 
                                                    name="<?php echo esc_attr($this->option_name); ?>[user_roles][]" 
                                                    value="<?php echo esc_attr($role_key); ?>"
                                                    <?php checked(in_array($role_key, $user_roles)); ?>
                                                />
                                                <strong><?php echo esc_html($role_name); ?></strong>
                                            </label>
                                        <?php endforeach; ?>
                                    </fieldset>
                                    <p class="description">
                                        Select which role(s) to assign to newly created users. You can select multiple roles.<br>
                                        Use role management plugins to create custom roles if needed.
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label>Product-Specific Role Assignment</label>
                                </th>
                                <td>
                                    <?php if (empty($stored_products)): ?>
                                        <p class="description" style="color: #dc3232;">
                                            ⚠️ No products detected yet. Make a test purchase or wait for a real sale to see your products here.
                                        </p>
                                    <?php else: ?>
                                        <div class="product-roles-repeater">
                                            <p class="description" style="margin-bottom: 15px;">
                                                Configure which roles should be assigned for each product purchase. If no roles are selected for a product, the default "Assign User Roles" setting above will be used.
                                            </p>
                                            
                                            <?php foreach ($stored_products as $product_id => $product_info): ?>
                                                <?php 
                                                $assigned_roles = isset($product_roles[$product_id]) ? $product_roles[$product_id] : array();
                                                $has_roles = !empty($assigned_roles);
                                                ?>
                                                <div class="product-role-item <?php echo $has_roles ? 'active' : ''; ?>">
                                                    <div class="product-role-header">
                                                        <div class="product-info">
                                                            <strong><?php echo esc_html($product_info['name']); ?></strong>
                                                            <code style="margin-left: 10px; color: #666;"><?php echo esc_html($product_id); ?></code>
                                                            <?php if ($has_roles): ?>
                                                                <span class="badge badge-configured">✓ Configured</span>
                                                            <?php endif; ?>
                                                        </div>
                                                        <form method="post" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this product?\n\nProduct: <?php echo esc_js($product_info['name']); ?>\nID: <?php echo esc_js($product_id); ?>\n\nThis will remove the product and its role configuration.');">
                                                            <?php wp_nonce_field('gumroad_delete_product'); ?>
                                                            <input type="hidden" name="product_id" value="<?php echo esc_attr($product_id); ?>" />
                                                            <button type="submit" name="delete_product" class="button-delete-product" title="Delete this product">
                                                                🗑️ Delete
                                                            </button>
                                                        </form>
                                                    </div>
                                                    
                                                    <div class="product-role-content">
                                                        <p class="role-section-label">Select roles to assign for this product:</p>
                                                        <div class="role-checkboxes">
                                                            <?php foreach ($available_roles as $role_key => $role_name): ?>
                                                                <label class="role-checkbox-label">
                                                                    <input 
                                                                        type="checkbox" 
                                                                        name="<?php echo esc_attr($this->option_name); ?>[product_roles][<?php echo esc_attr($product_id); ?>][]" 
                                                                        value="<?php echo esc_attr($role_key); ?>"
                                                                        <?php checked(in_array($role_key, $assigned_roles)); ?>
                                                                    />
                                                                    <strong><?php echo esc_html($role_name); ?></strong>
                                                                </label>
                                                            <?php endforeach; ?>
                                                        </div>
                                                        <p class="description" style="margin-top: 8px;">
                                                            💡 Leave all unchecked to use the default "Assign User Roles" setting above.
                                                        </p>
                                                    </div>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                        
                                        <p class="description" style="margin-top: 15px;">
                                            <strong>💡 How it works:</strong><br>
                                            • Configure specific roles for each product, or leave unchecked to use default roles<br>
                                            • Only products with assigned roles will trigger user creation<br>
                                            • If NO products have roles assigned, ALL purchases will create users with default roles (backward compatible)
                                        </p>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label for="email_subject">Welcome Email Subject</label>
                                </th>
                                <td>
                                    <input 
                                        type="text" 
                                        id="email_subject" 
                                        name="<?php echo esc_attr($this->option_name); ?>[email_subject]" 
                                        value="<?php echo esc_attr($email_subject); ?>" 
                                        class="regular-text"
                                        placeholder="Welcome! Your Account Has Been Created"
                                    />
                                    <p class="description">
                                        Subject line for the welcome email sent to new users. You can use dynamic tags like {{product_name}}, {{username}}, {{site_name}}
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label for="email_message">Custom Email Template (HTML)</label>
                                </th>
                                <td>
                                    <?php 
                                    // Show default template if empty
                                    $default_template = '<p>Hi there!</p>

<p>Thank you for your purchase of <strong>{{product_name}}</strong>!</p>

<p>Your account has been created on <strong>{{site_name}}</strong>.</p>

<h3>Your Login Credentials:</h3>
<ul>
    <li><strong>Username:</strong> {{username}}</li>
    <li><strong>Password:</strong> {{password}}</li>
    <li><strong>Login URL:</strong> <a href="{{login_url}}">{{login_url}}</a></li>
</ul>

<p>We recommend changing your password after your first login.</p>

<p>Alternatively, you can <a href="{{password_reset_url}}">reset your password here</a>.</p>

<p>Best regards,<br>
{{site_name}} Team</p>';
                                    $display_message = !empty($email_message) ? $email_message : $default_template;
                                    ?>
                                    <textarea 
                                        id="email_message" 
                                        name="<?php echo esc_attr($this->option_name); ?>[email_message]" 
                                        rows="16"
                                        class="large-text code"
                                        style="font-family: monospace; font-size: 13px;"
                                    ><?php echo esc_textarea($display_message); ?></textarea>
                                    
                                    <div class="email-tags-info" style="margin-top: 15px; background: #e7f5fe; padding: 15px; border-left: 4px solid #2271b1; border-radius: 4px;">
                                        <h4 style="margin-top: 0;">📧 Available Dynamic Tags:</h4>
                                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px;">
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{site_name}}</code>
                                                <span style="color: #666; font-size: 13px;"> - Your site name</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{site_url}}</code>
                                                <span style="color: #666; font-size: 13px;"> - Your site URL</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{product_name}}</code>
                                                <span style="color: #666; font-size: 13px;"> - Purchased product</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{username}}</code>
                                                <span style="color: #666; font-size: 13px;"> - User's username</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{password}}</code>
                                                <span style="color: #666; font-size: 13px;"> - Generated password</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{email}}</code>
                                                <span style="color: #666; font-size: 13px;"> - User's email</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{login_url}}</code>
                                                <span style="color: #666; font-size: 13px;"> - WordPress login URL</span>
                                            </div>
                                            <div>
                                                <code style="background: #fff; padding: 2px 6px; border-radius: 3px; color: #2271b1; font-weight: 600;">{{password_reset_url}}</code>
                                                <span style="color: #666; font-size: 13px;"> - Password reset link</span>
                                            </div>
                                        </div>
                                        <p style="margin-bottom: 0; margin-top: 15px; color: #2c3338;">
                                            <strong>💡 Tips:</strong><br>
                                            • Full HTML support - style your email as you wish!<br>
                                            • Use dynamic tags by wrapping them in double curly braces: <code style="background: #fff; padding: 2px 6px;">{{tag_name}}</code><br>
                                            • The template above shows the default email structure<br>
                                            • Emails are sent as HTML, so you can use any HTML tags and inline CSS
                                        </p>
                                    </div>
                                </td>
                            </tr>
                        </table>
                        
                        <?php submit_button('Save Settings', 'primary', 'save_gumroad_settings'); ?>
                    </form>
                </div>
                
                <!-- Endpoint Card -->
                <div class="gumroad-card gumroad-endpoint-card">
                    <details>
                        <summary><h2 style="display: inline; cursor: pointer;">🔗 Webhook Endpoint</h2></summary>
                        <div class="endpoint-content">
                            <p>Copy this URL and paste it into your <strong>Gumroad Account Settings</strong> under the "Ping" section:</p>
                            
                            <div class="endpoint-url-container">
                        <input 
                            type="text" 
                            id="endpoint-url" 
                            value="<?php echo esc_attr($endpoint_url); ?>" 
                            readonly 
                            class="endpoint-url-input"
                        />
                        <button type="button" class="button button-primary" onclick="copyEndpointUrl()">
                            📋 Copy URL
                        </button>
                    </div>
                    
                    <div class="security-notice">
                        <p><strong>🔒 Security Feature:</strong> This URL contains a unique hash that makes it impossible to guess. Only you know this URL, so unauthorized pings will receive a 404 error.</p>
                    </div>
                    
                    <!-- Refresh Hash Section -->
                    <div class="refresh-hash-section">
                        <h3>🔄 Refresh Endpoint Hash</h3>
                        <p>If your endpoint URL has been accidentally exposed or compromised, you can generate a new secure hash below.</p>
                        
                        <form method="post" onsubmit="return confirm('⚠️ WARNING: This will generate a new endpoint URL. You must update your Gumroad webhook settings with the new URL immediately, or incoming webhooks will stop working.\n\nAre you sure you want to continue?');">
                            <?php wp_nonce_field('gumroad_refresh_hash'); ?>
                            <button type="submit" name="refresh_endpoint_hash" class="button button-danger">
                                🔄 Refresh Endpoint Hash
                            </button>
                        </form>
                        
                        <div class="refresh-hash-warning">
                            <p><strong>⚠️ WARNING:</strong> Refreshing the hash will change your endpoint URL. After refreshing:</p>
                            <ul>
                                <li>Your old endpoint URL will <strong>immediately stop working</strong></li>
                                <li>You <strong>must update</strong> your Gumroad webhook settings with the new URL</li>
                                <li>Any webhooks sent to the old URL will be rejected</li>
                            </ul>
                            <p><strong>Only use this if your endpoint URL has been compromised or exposed publicly.</strong></p>
                        </div>
                    </div>
                    
                    <div class="endpoint-instructions">
                        <h3>📝 Setup Instructions:</h3>
                        <ol>
                            <li>Enter your <strong>Seller ID</strong> above and save settings</li>
                            <li>Enable "Auto Create Users" and select desired roles</li>
                            <li>Copy the ping endpoint URL above</li>
                            <li>Go to your <a href="https://app.gumroad.com/settings" target="_blank">Gumroad Account Settings</a></li>
                            <li>Find the <strong>"Ping"</strong> setting</li>
                            <li>Paste the endpoint URL</li>
                            <li>Test the connection using the <a href="<?php echo admin_url('admin.php?page=gumroad-connect-test'); ?>">Ping Test</a> page</li>
                        </ol>
                    </div>
                        </div>
                    </details>
                </div>
                
                <!-- Info Card -->
                <div class="gumroad-card gumroad-info-card">
                    <details>
                        <summary><h3 style="display: inline; cursor: pointer;">ℹ️ How It Works</h3></summary>
                        <div class="info-content">
                            <ul>
                                <li>When a customer purchases your product on Gumroad, a webhook is sent to your site</li>
                                <li>The plugin verifies the seller_id for security</li>
                                <li>If user creation is enabled, a new WordPress account is created with the customer's email</li>
                                <li>The user is assigned the roles you selected (e.g., "Paid Member" + "Subscriber")</li>
                                <li>An email is automatically sent with their login credentials</li>
                                <li>If the user already exists, the roles are simply added to their account</li>
                                <li>All actions are logged in the <a href="<?php echo admin_url('admin.php?page=gumroad-connect-users'); ?>">User Log</a></li>
                            </ul>
                        </div>
                    </details>
                </div>
                
            </div>
        </div>
        
        <script>
        function copyEndpointUrl() {
            var input = document.getElementById('endpoint-url');
            input.select();
            input.setSelectionRange(0, 99999);
            document.execCommand('copy');
            
            var button = event.target;
            var originalText = button.textContent;
            button.textContent = '✅ Copied!';
            button.style.backgroundColor = '#46b450';
            
            setTimeout(function() {
                button.textContent = originalText;
                button.style.backgroundColor = '';
            }, 2000);
        }
        </script>
        <?php
    }
    
    /**
     * Test page
     */
    public function test_page() {
        // Handle settings update
        if (isset($_POST['update_ping_settings']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'gumroad_ping_settings')) {
            $settings = get_option($this->option_name, array());
            
            if (isset($_POST[$this->option_name]['ping_log_limit'])) {
                $ping_log_limit = intval($_POST[$this->option_name]['ping_log_limit']);
                $settings['ping_log_limit'] = max(10, min(1000, $ping_log_limit));
            }
            
            if (isset($_POST[$this->option_name]['ping_per_page'])) {
                $ping_per_page = intval($_POST[$this->option_name]['ping_per_page']);
                $settings['ping_per_page'] = max(10, min(200, $ping_per_page));
            }
            
            update_option($this->option_name, $settings);
            echo '<div class="notice notice-success"><p>Ping log settings saved successfully!</p></div>';
        }
        
        // Handle clear log action
        if (isset($_POST['clear_log']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'gumroad_clear_log')) {
            delete_option($this->ping_log_option);
            echo '<div class="notice notice-success"><p>Ping log cleared successfully!</p></div>';
        }
        
        $ping_log = get_option($this->ping_log_option, array());
        $settings = get_option($this->option_name, array());
        $seller_id = isset($settings['seller_id']) ? $settings['seller_id'] : '';
        
        // Get log limits from settings
        $ping_log_limit = isset($settings['ping_log_limit']) ? intval($settings['ping_log_limit']) : 100;
        $ping_per_page = isset($settings['ping_per_page']) ? intval($settings['ping_per_page']) : 50;
        
        // Pagination
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $total_entries = count($ping_log);
        $total_pages = ceil($total_entries / $ping_per_page);
        $offset = ($current_page - 1) * $ping_per_page;
        $paged_log = array_slice($ping_log, $offset, $ping_per_page);
        
        ?>
        <div class="wrap gumroad-connect-wrap">
            <h1>🧪 Gumroad Connect - Ping Test</h1>
            
            <div class="gumroad-connect-container">
                
                <!-- Ping Log Settings -->
                <div class="gumroad-card">
                    <h2>⚙️ Ping Log Settings</h2>
                    <form method="post" action="">
                        <?php wp_nonce_field('gumroad_ping_settings'); ?>
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <label for="ping_log_limit">Storage Limit</label>
                                </th>
                                <td>
                                    <?php 
                                    $ping_log_limit = isset($settings['ping_log_limit']) ? $settings['ping_log_limit'] : 100;
                                    ?>
                                    <input 
                                        type="number" 
                                        id="ping_log_limit" 
                                        name="<?php echo esc_attr($this->option_name); ?>[ping_log_limit]" 
                                        value="<?php echo esc_attr($ping_log_limit); ?>"
                                        min="10"
                                        max="1000"
                                        class="small-text"
                                    />
                                    <p class="description">
                                        Maximum number of ping entries to store in database. Default: 100. Range: 10-1000.<br>
                                        Older entries are automatically deleted when this limit is exceeded.
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label for="ping_per_page">Entries Per Page</label>
                                </th>
                                <td>
                                    <?php 
                                    $ping_per_page = isset($settings['ping_per_page']) ? $settings['ping_per_page'] : 50;
                                    ?>
                                    <input 
                                        type="number" 
                                        id="ping_per_page" 
                                        name="<?php echo esc_attr($this->option_name); ?>[ping_per_page]" 
                                        value="<?php echo esc_attr($ping_per_page); ?>"
                                        min="10"
                                        max="200"
                                        class="small-text"
                                    />
                                    <p class="description">
                                        Number of ping entries to display per page. Default: 50. Range: 10-200.
                                    </p>
                                </td>
                            </tr>
                        </table>
                        
                        <button type="submit" name="update_ping_settings" class="button button-primary">Save Settings</button>
                    </form>
                </div>
                
                <!-- Test Instructions -->
                <div class="gumroad-card">
                    <h2>📡 Test Your Connection</h2>
                    <p>This page displays incoming webhook pings from Gumroad in real-time.</p>
                    
                    <div class="test-instructions">
                        <h3>How to test:</h3>
                        <ol>
                            <li>Make sure you've saved your Seller ID in <a href="<?php echo admin_url('admin.php?page=gumroad-connect'); ?>">Settings</a></li>
                            <li>Add the webhook URL to your Gumroad account</li>
                            <li>Make a test purchase of your own product (or use Gumroad's test mode)</li>
                            <li>Refresh this page to see the incoming ping data</li>
                        </ol>
                        
                        <p><strong>Configured Seller ID:</strong> 
                            <?php if ($seller_id): ?>
                                <code><?php echo esc_html($seller_id); ?></code>
                            <?php else: ?>
                                <span style="color: #dc3232;">⚠️ Not configured - <a href="<?php echo admin_url('admin.php?page=gumroad-connect'); ?>">Set it now</a></span>
                            <?php endif; ?>
                        </p>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <form method="post" style="display: inline;">
                            <?php wp_nonce_field('gumroad_clear_log'); ?>
                            <button type="submit" name="clear_log" class="button" onclick="return confirm('Are you sure you want to clear all ping logs?')">
                                🗑️ Clear Ping Log
                            </button>
                        </form>
                        <button type="button" class="button button-primary" onclick="location.reload()">
                            🔄 Refresh Page
                        </button>
                    </div>
                </div>
                
                <!-- Ping Log -->
                <div class="gumroad-card">
                    <h2>📬 Received Pings (Storing Last <?php echo $ping_log_limit; ?>)</h2>
                    
                    <?php if ($total_entries > 0): ?>
                        <div class="log-stats">
                            <p>Showing <?php echo count($paged_log); ?> of <?php echo $total_entries; ?> entries (Page <?php echo $current_page; ?> of <?php echo $total_pages; ?>)</p>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (empty($ping_log)): ?>
                        <div class="no-pings">
                            <p>🔍 No pings received yet.</p>
                            <p>Make a test purchase or wait for a real sale to see data here.</p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($paged_log as $index => $entry): ?>
                            <div class="ping-entry <?php echo $entry['seller_id_match'] ? 'verified' : 'unverified'; ?>">
                                <div class="ping-header">
                                    <strong>Ping #<?php echo ($offset + $index + 1); ?></strong>
                                    <span class="ping-time"><?php echo esc_html($entry['datetime_readable']); ?></span>
                                    <?php if ($entry['seller_id_match']): ?>
                                        <span class="badge badge-success">✅ Verified</span>
                                    <?php else: ?>
                                        <span class="badge badge-warning">⚠️ Seller ID Mismatch</span>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="ping-details">
                                    <details>
                                        <summary><strong>📦 View Full Data</strong></summary>
                                        
                                        <h4>POST Data:</h4>
                                        <pre><?php echo esc_html(json_encode($entry['data'], JSON_PRETTY_PRINT)); ?></pre>
                                        
                                        <h4>Headers:</h4>
                                        <pre><?php echo esc_html(json_encode($entry['headers'], JSON_PRETTY_PRINT)); ?></pre>
                                        
                                        <h4>Verification:</h4>
                                        <pre><?php 
                                        echo "Stored Seller ID: " . esc_html($entry['stored_seller_id']) . "\n";
                                        echo "Received Seller ID: " . (isset($entry['data']['seller_id']) ? esc_html($entry['data']['seller_id']) : 'N/A') . "\n";
                                        echo "Match: " . ($entry['seller_id_match'] ? 'YES ✅' : 'NO ❌');
                                        ?></pre>
                                    </details>
                                    
                                    <!-- Quick Info -->
                                    <?php if (!empty($entry['data'])): ?>
                                        <div class="quick-info">
                                            <h4>Quick Info:</h4>
                                            <table>
                                                <?php foreach ($entry['data'] as $key => $value): ?>
                                                    <?php if (in_array($key, ['sale_id', 'product_name', 'email', 'price', 'seller_id', 'product_id'])): ?>
                                                        <tr>
                                                            <td><strong><?php echo esc_html($key); ?>:</strong></td>
                                                            <td><?php echo esc_html(is_array($value) ? json_encode($value) : $value); ?></td>
                                                        </tr>
                                                    <?php endif; ?>
                                                <?php endforeach; ?>
                                            </table>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        
                        <!-- Pagination -->
                        <?php if ($total_pages > 1): ?>
                            <div class="tablenav">
                                <div class="tablenav-pages">
                                    <span class="displaying-num"><?php echo $total_entries; ?> items</span>
                                    <span class="pagination-links">
                                        <?php
                                        $base_url = admin_url('admin.php?page=gumroad-connect-test');
                                        
                                        if ($current_page > 1) {
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=1') . '">« First</a> ';
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=' . ($current_page - 1)) . '">‹ Previous</a> ';
                                        }
                                        
                                        echo '<span class="paging-input">';
                                        echo '<span class="tablenav-paging-text">';
                                        echo $current_page . ' of <span class="total-pages">' . $total_pages . '</span>';
                                        echo '</span>';
                                        echo '</span> ';
                                        
                                        if ($current_page < $total_pages) {
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=' . ($current_page + 1)) . '">Next ›</a> ';
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=' . $total_pages) . '">Last »</a>';
                                        }
                                        ?>
                                    </span>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
                
            </div>
        </div>
        <?php
    }
    
    /**
     * User log page
     */
    public function user_log_page() {
        // Handle settings update
        if (isset($_POST['update_user_settings']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'gumroad_user_settings')) {
            $settings = get_option($this->option_name, array());
            
            if (isset($_POST[$this->option_name]['user_log_limit'])) {
                $user_log_limit = intval($_POST[$this->option_name]['user_log_limit']);
                $settings['user_log_limit'] = max(10, min(1000, $user_log_limit));
            }
            
            if (isset($_POST[$this->option_name]['user_per_page'])) {
                $user_per_page = intval($_POST[$this->option_name]['user_per_page']);
                $settings['user_per_page'] = max(10, min(200, $user_per_page));
            }
            
            update_option($this->option_name, $settings);
            echo '<div class="notice notice-success"><p>User log settings saved successfully!</p></div>';
        }
        
        // Handle clear log action
        if (isset($_POST['clear_user_log']) && isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], 'gumroad_clear_user_log')) {
            delete_option($this->user_log_option);
            echo '<div class="notice notice-success"><p>User log cleared successfully!</p></div>';
        }
        
        $user_log = get_option($this->user_log_option, array());
        $settings = get_option($this->option_name, array());
        
        // Get log limits from settings
        $user_log_limit = isset($settings['user_log_limit']) ? intval($settings['user_log_limit']) : 100;
        $user_per_page = isset($settings['user_per_page']) ? intval($settings['user_per_page']) : 50;
        
        // Pagination
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $total_entries = count($user_log);
        $total_pages = ceil($total_entries / $user_per_page);
        $offset = ($current_page - 1) * $user_per_page;
        $paged_log = array_slice($user_log, $offset, $user_per_page);
        
        ?>
        <div class="wrap gumroad-connect-wrap">
            <h1>👥 Gumroad Connect - User Log</h1>
            
            <div class="gumroad-connect-container">
                
                <!-- User Log Settings -->
                <div class="gumroad-card">
                    <h2>⚙️ User Log Settings</h2>
                    <form method="post" action="">
                        <?php wp_nonce_field('gumroad_user_settings'); ?>
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <label for="user_log_limit">Storage Limit</label>
                                </th>
                                <td>
                                    <?php 
                                    $user_log_limit = isset($settings['user_log_limit']) ? $settings['user_log_limit'] : 100;
                                    ?>
                                    <input 
                                        type="number" 
                                        id="user_log_limit" 
                                        name="<?php echo esc_attr($this->option_name); ?>[user_log_limit]" 
                                        value="<?php echo esc_attr($user_log_limit); ?>"
                                        min="10"
                                        max="1000"
                                        class="small-text"
                                    />
                                    <p class="description">
                                        Maximum number of user action entries to store in database. Default: 100. Range: 10-1000.<br>
                                        Older entries are automatically deleted when this limit is exceeded.
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label for="user_per_page">Entries Per Page</label>
                                </th>
                                <td>
                                    <?php 
                                    $user_per_page = isset($settings['user_per_page']) ? $settings['user_per_page'] : 50;
                                    ?>
                                    <input 
                                        type="number" 
                                        id="user_per_page" 
                                        name="<?php echo esc_attr($this->option_name); ?>[user_per_page]" 
                                        value="<?php echo esc_attr($user_per_page); ?>"
                                        min="10"
                                        max="200"
                                        class="small-text"
                                    />
                                    <p class="description">
                                        Number of user action entries to display per page. Default: 50. Range: 10-200.
                                    </p>
                                </td>
                            </tr>
                        </table>
                        
                        <button type="submit" name="update_user_settings" class="button button-primary">Save Settings</button>
                    </form>
                </div>
                
                <!-- User Log Header -->
                <div class="gumroad-card">
                    <h2>📊 User Creation Log</h2>
                    <p>This page shows all users created or updated through Gumroad purchases.</p>
                    
                    <div style="margin-top: 20px;">
                        <form method="post" style="display: inline;">
                            <?php wp_nonce_field('gumroad_clear_user_log'); ?>
                            <button type="submit" name="clear_user_log" class="button" onclick="return confirm('Are you sure you want to clear the user log?')">
                                🗑️ Clear User Log
                            </button>
                        </form>
                        <button type="button" class="button button-primary" onclick="location.reload()">
                            🔄 Refresh Page
                        </button>
                    </div>
                </div>
                
                <!-- User Log Entries -->
                <div class="gumroad-card">
                    <h2>👤 User Actions (Storing Last <?php echo $user_log_limit; ?>)</h2>
                    
                    <?php if ($total_entries > 0): ?>
                        <div class="log-stats">
                            <p>Showing <?php echo count($paged_log); ?> of <?php echo $total_entries; ?> entries (Page <?php echo $current_page; ?> of <?php echo $total_pages; ?>)</p>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (empty($user_log)): ?>
                        <div class="no-pings">
                            <p>🔍 No user actions logged yet.</p>
                            <p>Users will appear here when they're created through Gumroad purchases.</p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($paged_log as $index => $entry): ?>
                            <?php 
                            $result = $entry['result'];
                            $status = $result['status'];
                            $status_class = '';
                            $status_icon = '';
                            
                            switch ($status) {
                                case 'created':
                                    $status_class = 'status-created';
                                    $status_icon = '✅';
                                    break;
                                case 'existing':
                                    $status_class = 'status-existing';
                                    $status_icon = '🔄';
                                    break;
                                case 'cancelled':
                                    $status_class = 'status-cancelled';
                                    $status_icon = '🚫';
                                    break;
                                case 'error':
                                    $status_class = 'status-error';
                                    $status_icon = '❌';
                                    break;
                                case 'skipped':
                                    $status_class = 'status-skipped';
                                    $status_icon = '⏭️';
                                    break;
                            }
                            ?>
                            
                            <div class="user-log-entry <?php echo esc_attr($status_class); ?>">
                                <div class="user-log-header">
                                    <strong><?php echo $status_icon; ?> Action #<?php echo ($offset + $index + 1); ?></strong>
                                    <span class="user-log-time"><?php echo esc_html($entry['datetime_readable']); ?></span>
                                    <span class="badge badge-status"><?php echo esc_html(ucfirst($status)); ?></span>
                                </div>
                                
                                <div class="user-log-content">
                                    <table class="user-info-table">
                                        <tr>
                                            <td><strong>Email:</strong></td>
                                            <td><?php echo esc_html($result['email']); ?></td>
                                        </tr>
                                        <?php if (isset($result['username'])): ?>
                                            <tr>
                                                <td><strong>Username:</strong></td>
                                                <td><?php echo esc_html($result['username']); ?></td>
                                            </tr>
                                        <?php endif; ?>
                                        <tr>
                                            <td><strong>User ID:</strong></td>
                                            <td>
                                                <?php if ($result['user_id']): ?>
                                                    <a href="<?php echo admin_url('user-edit.php?user_id=' . $result['user_id']); ?>" target="_blank">
                                                        #<?php echo esc_html($result['user_id']); ?>
                                                    </a>
                                                <?php else: ?>
                                                    N/A
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                        <?php if (isset($result['roles'])): ?>
                                            <tr>
                                                <td><strong>Roles Assigned:</strong></td>
                                                <td><?php echo esc_html(implode(', ', $result['roles'])); ?></td>
                                            </tr>
                                        <?php endif; ?>
                                        <?php if (isset($result['roles_removed'])): ?>
                                            <tr>
                                                <td><strong>Roles Removed:</strong></td>
                                                <td><?php echo esc_html(implode(', ', $result['roles_removed'])); ?></td>
                                            </tr>
                                        <?php endif; ?>
                                        <?php if (isset($result['subscription_id'])): ?>
                                            <tr>
                                                <td><strong>Subscription ID:</strong></td>
                                                <td><code><?php echo esc_html($result['subscription_id']); ?></code></td>
                                            </tr>
                                        <?php endif; ?>
                                        <tr>
                                            <td><strong>Password Email:</strong></td>
                                            <td>
                                                <?php if ($result['password_sent']): ?>
                                                    <span style="color: #46b450;">✅ Sent</span>
                                                <?php else: ?>
                                                    <span style="color: #dc3232;">❌ Not Sent</span>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td><strong>Product:</strong></td>
                                            <td><?php echo esc_html($entry['gumroad_data']['product_name']); ?></td>
                                        </tr>
                                        <tr>
                                            <td><strong>Price:</strong></td>
                                            <td>$<?php echo number_format($entry['gumroad_data']['price'] / 100, 2); ?></td>
                                        </tr>
                                        <tr>
                                            <td><strong>Test Mode:</strong></td>
                                            <td><?php echo ($entry['gumroad_data']['test'] === 'true') ? '🧪 Yes' : 'No'; ?></td>
                                        </tr>
                                        <tr>
                                            <td><strong>Message:</strong></td>
                                            <td><?php echo esc_html($result['message']); ?></td>
                                        </tr>
                                    </table>
                                    
                                    <details style="margin-top: 10px;">
                                        <summary><strong>🔍 View Full Details</strong></summary>
                                        <pre><?php echo esc_html(json_encode($entry, JSON_PRETTY_PRINT)); ?></pre>
                                    </details>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        
                        <!-- Pagination -->
                        <?php if ($total_pages > 1): ?>
                            <div class="tablenav">
                                <div class="tablenav-pages">
                                    <span class="displaying-num"><?php echo $total_entries; ?> items</span>
                                    <span class="pagination-links">
                                        <?php
                                        $base_url = admin_url('admin.php?page=gumroad-connect-users');
                                        
                                        if ($current_page > 1) {
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=1') . '">« First</a> ';
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=' . ($current_page - 1)) . '">‹ Previous</a> ';
                                        }
                                        
                                        echo '<span class="paging-input">';
                                        echo '<span class="tablenav-paging-text">';
                                        echo $current_page . ' of <span class="total-pages">' . $total_pages . '</span>';
                                        echo '</span>';
                                        echo '</span> ';
                                        
                                        if ($current_page < $total_pages) {
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=' . ($current_page + 1)) . '">Next ›</a> ';
                                            echo '<a class="button" href="' . esc_url($base_url . '&paged=' . $total_pages) . '">Last »</a>';
                                        }
                                        ?>
                                    </span>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
                
            </div>
        </div>
        <?php
    }
    
    /**
     * Enqueue admin styles
     */
    public function enqueue_admin_styles($hook) {
        if (strpos($hook, 'gumroad-connect') === false) {
            return;
        }
        
        wp_add_inline_style('wp-admin', $this->get_admin_css());
    }
    
    /**
     * Get admin CSS
     */
    private function get_admin_css() {
        return '
        .gumroad-connect-wrap {
            background: #f0f0f1;
            margin-left: -20px;
            padding: 20px;
        }
        
        .gumroad-connect-container {
            max-width: 1200px;
        }
        
        .gumroad-card {
            background: white;
            border: 1px solid #c3c4c7;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 1px rgba(0,0,0,.04);
        }
        
        .gumroad-card h2 {
            margin-top: 0;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        
        .gumroad-card h3 {
            margin-top: 20px;
        }
        
        .endpoint-url-container {
            display: flex;
            gap: 10px;
            margin: 15px 0;
        }
        
        .endpoint-url-input {
            flex: 1;
            padding: 10px;
            font-family: monospace;
            font-size: 13px;
            background: #f6f7f7;
            border: 1px solid #c3c4c7;
            border-radius: 4px;
        }
        
        .endpoint-instructions ol {
            background: #f6f7f7;
            padding: 20px 20px 20px 40px;
            border-left: 4px solid #2271b1;
            border-radius: 4px;
        }
        
        .endpoint-instructions li {
            margin-bottom: 10px;
        }
        
        .gumroad-info-card ul {
            background: #e7f5fe;
            padding: 15px 15px 15px 35px;
            border-left: 4px solid #2271b1;
            border-radius: 4px;
        }
        
        .test-instructions {
            background: #e7f5fe;
            padding: 15px;
            border-left: 4px solid #2271b1;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        
        .ping-entry {
            background: #f9f9f9;
            border: 2px solid #ddd;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .ping-entry.verified {
            border-color: #46b450;
            background: #f0f9f1;
        }
        
        .ping-entry.unverified {
            border-color: #ffb900;
            background: #fff8e5;
        }
        
        .ping-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .ping-time {
            color: #666;
            font-size: 13px;
        }
        
        .badge {
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .badge-success {
            background: #46b450;
            color: white;
        }
        
        .badge-warning {
            background: #ffb900;
            color: #000;
        }
        
        .badge-custom {
            background: #8c4fff;
            color: white;
        }
        
        .badge-status {
            background: #2271b1;
            color: white;
        }
        
        .ping-details pre {
            background: #2c3338;
            color: #f0f0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
            line-height: 1.6;
        }
        
        .ping-details details {
            margin-top: 10px;
        }
        
        .ping-details summary {
            cursor: pointer;
            color: #2271b1;
            font-weight: 500;
            padding: 8px;
            background: #f0f0f1;
            border-radius: 4px;
        }
        
        .ping-details summary:hover {
            background: #dcdcde;
        }
        
        .endpoint-content,
        .info-content {
            margin-top: 15px;
        }
        
        details summary h2,
        details summary h3 {
            display: inline;
            margin: 0;
        }
        
        details summary {
            cursor: pointer;
            list-style: none;
        }
        
        details summary::-webkit-details-marker {
            display: none;
        }
        
        details summary::before {
            content: "▶ ";
            display: inline-block;
            transition: transform 0.2s;
        }
        
        details[open] summary::before {
            transform: rotate(90deg);
        }
        
        .quick-info {
            margin-top: 15px;
            background: white;
            padding: 10px;
            border-radius: 4px;
        }
        
        .quick-info table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .quick-info td {
            padding: 5px 10px;
            border-bottom: 1px solid #f0f0f1;
        }
        
        .quick-info td:first-child {
            width: 150px;
        }
        
        .no-pings {
            text-align: center;
            padding: 40px 20px;
            color: #666;
        }
        
        .no-pings p:first-child {
            font-size: 18px;
            font-weight: 500;
        }
        
        /* User Log Styles */
        .user-log-entry {
            background: #f9f9f9;
            border: 2px solid #ddd;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .user-log-entry.status-created {
            border-color: #46b450;
            background: #f0f9f1;
        }
        
        .user-log-entry.status-existing {
            border-color: #2271b1;
            background: #e7f5fe;
        }
        
        .user-log-entry.status-error {
            border-color: #dc3232;
            background: #fef7f7;
        }
        
        .user-log-entry.status-skipped {
            border-color: #999;
            background: #f5f5f5;
        }
        
        .user-log-entry.status-cancelled {
            border-color: #ff6b00;
            background: #fff5ed;
        }
        
        .user-log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .user-log-time {
            color: #666;
            font-size: 13px;
        }
        
        .user-info-table {
            width: 100%;
            background: white;
            border-radius: 4px;
            padding: 10px;
        }
        
        .user-info-table td {
            padding: 8px 10px;
            border-bottom: 1px solid #f0f0f1;
        }
        
        .user-info-table td:first-child {
            width: 180px;
            color: #666;
        }
        
        .user-log-content pre {
            background: #2c3338;
            color: #f0f0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
            line-height: 1.6;
            margin-top: 10px;
        }
        
        .user-log-content details summary {
            cursor: pointer;
            color: #2271b1;
            font-weight: 500;
            padding: 8px;
            background: #f0f0f1;
            border-radius: 4px;
        }
        
        .user-log-content details summary:hover {
            background: #dcdcde;
        }
        
        /* Pagination Styles */
        .tablenav {
            margin-top: 20px;
            padding: 15px;
            background: #f6f7f7;
            border-radius: 4px;
        }
        
        .tablenav-pages {
            text-align: center;
        }
        
        .displaying-num {
            margin-right: 15px;
            color: #666;
        }
        
        .pagination-links {
            display: inline-block;
        }
        
        .pagination-links .button {
            margin: 0 3px;
        }
        
        .paging-input {
            margin: 0 10px;
        }
        
        .log-stats {
            background: #f6f7f7;
            padding: 10px 15px;
            border-radius: 4px;
            margin-bottom: 15px;
        }
        
        .log-stats p {
            margin: 0;
            color: #666;
            font-size: 13px;
        }
        
        .security-notice {
            background: #e7f5e7;
            border-left: 4px solid #46b450;
            padding: 12px 15px;
            margin-top: 15px;
            border-radius: 4px;
        }
        
        .security-notice p {
            margin: 0;
            color: #2c662d;
        }
        
        /* Refresh Hash Section */
        .refresh-hash-section {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #e5e5e5;
        }
        
        .refresh-hash-section h3 {
            margin-top: 0;
            margin-bottom: 10px;
        }
        
        .button-danger {
            background: #dc3232 !important;
            border-color: #dc3232 !important;
            color: white !important;
            text-shadow: none !important;
            font-weight: 600;
        }
        
        .button-danger:hover {
            background: #a00 !important;
            border-color: #a00 !important;
        }
        
        .refresh-hash-warning {
            background: #fef7f7;
            border-left: 4px solid #dc3232;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }
        
        .refresh-hash-warning p {
            margin: 10px 0;
            color: #8a2424;
        }
        
        .refresh-hash-warning strong {
            color: #dc3232;
        }
        
        .refresh-hash-warning ul {
            margin: 10px 0;
            padding-left: 20px;
            color: #8a2424;
        }
        
        .refresh-hash-warning li {
            margin: 5px 0;
        }
        
        /* Product Roles Repeater Styles */
        .product-roles-repeater {
            background: #f6f7f7;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #c3c4c7;
        }
        
        .product-role-item {
            background: white;
            border: 2px solid #ddd;
            border-radius: 6px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .product-role-item.active {
            border-color: #2271b1;
            box-shadow: 0 0 0 1px #2271b1;
        }
        
        .product-role-header {
            padding: 12px 15px;
            background: #f9f9f9;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .product-role-item.active .product-role-header {
            background: #e7f5fe;
            border-bottom-color: #2271b1;
        }
        
        .product-info {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .badge-configured {
            background: #46b450;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .product-role-content {
            padding: 15px;
        }
        
        .role-section-label {
            margin: 0 0 10px 0;
            font-weight: 600;
            color: #1d2327;
        }
        
        .role-checkboxes {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 8px;
        }
        
        .role-checkbox-label {
            display: flex;
            align-items: center;
            padding: 8px 10px;
            background: #f6f7f7;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .role-checkbox-label:hover {
            background: #e7f5fe;
            border-color: #2271b1;
        }
        
        .role-checkbox-label input[type="checkbox"] {
            margin-right: 8px;
        }
        
        .role-checkbox-label input[type="checkbox"]:checked + strong {
            color: #2271b1;
        }
        
        /* Delete Product Button */
        .button-delete-product {
            background: #dc3232;
            color: white;
            border: 1px solid #dc3232;
            padding: 4px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        
        .button-delete-product:hover {
            background: #a00;
            border-color: #a00;
            color: white;
        }
        ';
    }
}

// Initialize the plugin
new Gumroad_Connect();

