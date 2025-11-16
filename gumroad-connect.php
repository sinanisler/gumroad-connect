<?php           
/**
 * Plugin Name: Gumroad Connect
 * Plugin URI: https://github.com/sinanisler/gumroad-connect
 * Description: Connect your WordPress site with Gumroad to automatically create user accounts when customers make a purchase.
 * Version: 1.12
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
     * Activate plugin - Create custom role and generate endpoint hash
     */
    public function activate_plugin() {
        // Get subscriber capabilities
        $subscriber = get_role('subscriber');
        
        if ($subscriber && !get_role('paidmember')) {
            // Add custom "paidmember" role with subscriber capabilities
            add_role('paidmember', 'Paid Member', $subscriber->capabilities);
        }
        
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
            array($this, 'sanitize_settings')
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
        
        if (isset($input['user_roles']) && is_array($input['user_roles'])) {
            $sanitized['user_roles'] = array_map('sanitize_text_field', $input['user_roles']);
        }
        
        if (isset($input['email_subject'])) {
            $sanitized['email_subject'] = sanitize_text_field($input['email_subject']);
        }
        
        if (isset($input['email_message'])) {
            $sanitized['email_message'] = wp_kses_post($input['email_message']);
        }
        
        if (isset($input['selected_products']) && is_array($input['selected_products'])) {
            $sanitized['selected_products'] = array_map('sanitize_text_field', $input['selected_products']);
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
        
        // Store in ping log (keep last 20 pings)
        $ping_log = get_option($this->ping_log_option, array());
        array_unshift($ping_log, $log_entry);
        $ping_log = array_slice($ping_log, 0, 20);
        update_option($this->ping_log_option, $ping_log);
        
        // Store product information for selection in settings
        if (isset($params['short_product_id']) && isset($params['product_name'])) {
            $this->store_product_info($params['short_product_id'], $params['product_name']);
        }
        
        // Process user creation if enabled and verified
        $user_creation_result = null;
        if ($create_users && $seller_id_match && isset($params['email'])) {
            // Check if product selection is enabled and if this product is selected
            $selected_products = isset($settings['selected_products']) ? $settings['selected_products'] : array();
            $short_product_id = isset($params['short_product_id']) ? $params['short_product_id'] : '';
            
            // If no products are selected, create users for all purchases (backward compatibility)
            // If products are selected, only create users for selected products
            if (empty($selected_products) || in_array($short_product_id, $selected_products)) {
                $user_creation_result = $this->create_or_update_user($params);
            } else {
                $user_creation_result = array(
                    'status' => 'skipped',
                    'message' => 'Product not selected for user creation',
                    'product_id' => $short_product_id,
                );
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
        $user_roles = isset($settings['user_roles']) ? $settings['user_roles'] : array('paidmember', 'subscriber');
        
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
        
        $message = "Hi there!\n\n";
        $message .= "Thank you for your purchase of {$product_name}!\n\n";
        $message .= "Your account has been created on {$site_name}.\n\n";
        
        // Add custom message if set
        if (!empty($custom_message)) {
            $message .= strip_tags($custom_message) . "\n\n";
        }
        
        $message .= "Here are your login credentials:\n\n";
        $message .= "Username: {$username}\n";
        $message .= "Password: {$password}\n";
        $message .= "Login URL: {$login_url}\n\n";
        $message .= "We recommend changing your password after your first login.\n\n";
        $message .= "Best regards,\n";
        $message .= "{$site_name} Team";
        
        // Send email
        $headers = array('Content-Type: text/plain; charset=UTF-8');
        return wp_mail($email, $subject, $message, $headers);
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
        
        // Store in user log (keep last 100 entries)
        $user_log = get_option($this->user_log_option, array());
        array_unshift($user_log, $log_entry);
        $user_log = array_slice($user_log, 0, 100);
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
        // Handle hash refresh action
        if (isset($_POST['refresh_endpoint_hash']) && check_admin_referer('gumroad_refresh_hash')) {
            $this->generate_endpoint_hash();
            echo '<div class="notice notice-success"><p><strong>✅ Endpoint hash refreshed successfully!</strong> Make sure to update your Gumroad webhook URL with the new endpoint.</p></div>';
        }
        
        $settings = get_option($this->option_name, array());
        $seller_id = isset($settings['seller_id']) ? $settings['seller_id'] : '';
        $create_users = isset($settings['create_users']) ? $settings['create_users'] : true;
        $user_roles = isset($settings['user_roles']) ? $settings['user_roles'] : array('paidmember', 'subscriber');
        $email_subject = isset($settings['email_subject']) ? $settings['email_subject'] : 'Welcome! Your Account Has Been Created';
        $email_message = isset($settings['email_message']) ? $settings['email_message'] : '';
        $selected_products = isset($settings['selected_products']) ? $settings['selected_products'] : array();
        
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
                    <form method="post" action="options.php">
                        <?php
                        settings_fields('gumroad_connect_settings_group');
                        ?>
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <label for="seller_id">Seller ID</label>
                                </th>
                                <td>
                                    <input 
                                        type="password" 
                                        id="seller_id" 
                                        name="<?php echo esc_attr($this->option_name); ?>[seller_id]" 
                                        value="<?php echo esc_attr($seller_id); ?>" 
                                        class="regular-text"
                                        placeholder="RcuODgh_........"
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
                                                <?php if ($role_key === 'paidmember'): ?>
                                                    <span class="badge badge-custom">Custom Role</span>
                                                <?php endif; ?>
                                            </label>
                                        <?php endforeach; ?>
                                    </fieldset>
                                    <p class="description">
                                        Select which role(s) to assign to newly created users. You can select multiple roles.<br>
                                        <strong>Recommended:</strong> "Paid Member" (custom) + "Subscriber" (default)
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label>Select Products for User Creation</label>
                                </th>
                                <td>
                                    <?php if (empty($stored_products)): ?>
                                        <p class="description" style="color: #dc3232;">
                                            ⚠️ No products detected yet. Make a test purchase or wait for a real sale to see your products here.
                                        </p>
                                    <?php else: ?>
                                        <fieldset>
                                            <p class="description" style="margin-bottom: 10px;">
                                                Select which products should trigger user creation. Leave all unchecked to create users for <strong>all purchases</strong> (default behavior).
                                            </p>
                                            <?php foreach ($stored_products as $product_id => $product_info): ?>
                                                <label style="display: block; margin-bottom: 8px; padding: 8px; background: #f6f7f7; border-radius: 4px;">
                                                    <input 
                                                        type="checkbox" 
                                                        name="<?php echo esc_attr($this->option_name); ?>[selected_products][]" 
                                                        value="<?php echo esc_attr($product_id); ?>"
                                                        <?php checked(in_array($product_id, $selected_products)); ?>
                                                    />
                                                    <strong><?php echo esc_html($product_info['name']); ?></strong>
                                                    <code style="margin-left: 10px; color: #666;"><?php echo esc_html($product_id); ?></code>
                                                </label>
                                            <?php endforeach; ?>
                                        </fieldset>
                                        <p class="description" style="margin-top: 10px;">
                                            💡 <strong>Tip:</strong> This allows you to have multiple products on Gumroad but only create WordPress users for specific products.
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
                                        Subject line for the welcome email sent to new users.
                                    </p>
                                </td>
                            </tr>
                            
                            <tr>
                                <th scope="row">
                                    <label for="email_message">Custom Email Message</label>
                                </th>
                                <td>
                                    <textarea 
                                        id="email_message" 
                                        name="<?php echo esc_attr($this->option_name); ?>[email_message]" 
                                        rows="6"
                                        class="large-text"
                                        placeholder="Add a custom message to include in the welcome email (optional)"
                                    ><?php echo esc_textarea($email_message); ?></textarea>
                                    <p class="description">
                                        This message will be included in the welcome email, before the login credentials.<br>
                                        Leave empty to use the default message.
                                    </p>
                                </td>
                            </tr>
                        </table>
                        
                        <?php submit_button('Save Settings'); ?>
                    </form>
                </div>
                
                <!-- Endpoint Card -->
                <div class="gumroad-card gumroad-endpoint-card">
                    <h2>🔗 Webhook Endpoint</h2>
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
                
                <!-- Info Card -->
                <div class="gumroad-card gumroad-info-card">
                    <h3>ℹ️ How It Works</h3>
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
        // Handle clear log action
        if (isset($_POST['clear_log']) && check_admin_referer('gumroad_clear_log')) {
            delete_option($this->ping_log_option);
            echo '<div class="notice notice-success"><p>Ping log cleared successfully!</p></div>';
        }
        
        $ping_log = get_option($this->ping_log_option, array());
        $settings = get_option($this->option_name, array());
        $seller_id = isset($settings['seller_id']) ? $settings['seller_id'] : '';
        
        ?>
        <div class="wrap gumroad-connect-wrap">
            <h1>🧪 Gumroad Connect - Ping Test</h1>
            
            <div class="gumroad-connect-container">
                
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
                    <h2>📬 Received Pings (Last 20)</h2>
                    
                    <?php if (empty($ping_log)): ?>
                        <div class="no-pings">
                            <p>🔍 No pings received yet.</p>
                            <p>Make a test purchase or wait for a real sale to see data here.</p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($ping_log as $index => $entry): ?>
                            <div class="ping-entry <?php echo $entry['seller_id_match'] ? 'verified' : 'unverified'; ?>">
                                <div class="ping-header">
                                    <strong>Ping #<?php echo ($index + 1); ?></strong>
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
        // Handle clear log action
        if (isset($_POST['clear_user_log']) && check_admin_referer('gumroad_clear_user_log')) {
            delete_option($this->user_log_option);
            echo '<div class="notice notice-success"><p>User log cleared successfully!</p></div>';
        }
        
        $user_log = get_option($this->user_log_option, array());
        
        // Pagination
        $per_page = 100;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $total_entries = count($user_log);
        $total_pages = ceil($total_entries / $per_page);
        $offset = ($current_page - 1) * $per_page;
        $paged_log = array_slice($user_log, $offset, $per_page);
        
        ?>
        <div class="wrap gumroad-connect-wrap">
            <h1>👥 Gumroad Connect - User Log</h1>
            
            <div class="gumroad-connect-container">
                
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
                    <h2>👤 User Actions (Last 100)</h2>
                    
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
        ';
    }
}

// Initialize the plugin
new Gumroad_Connect();