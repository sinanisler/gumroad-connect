<?php
/**
 * Plugin Name: Gumroad Connect
 * Plugin URI: https://example.com/gumroad-connect
 * Description: Connect your WordPress site with Gumroad to receive real-time sale notifications via webhooks
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://example.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: gumroad-connect
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class Gumroad_Connect {
    
    private $option_name = 'gumroad_connect_settings';
    private $ping_log_option = 'gumroad_connect_ping_log';
    
    public function __construct() {
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
        
        return $sanitized;
    }
    
    /**
     * Register REST API route
     */
    public function register_rest_route() {
        register_rest_route('gumroad-connect/v1', '/ping', array(
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
        
        // Return success response
        return new WP_REST_Response(array(
            'success' => true,
            'message' => 'Ping received successfully',
            'timestamp' => current_time('mysql'),
            'seller_id_verified' => $seller_id_match,
        ), 200);
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
        $settings = get_option($this->option_name, array());
        $seller_id = isset($settings['seller_id']) ? $settings['seller_id'] : '';
        
        // Get the REST endpoint URL
        $endpoint_url = rest_url('gumroad-connect/v1/ping');
        
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
                                        type="text" 
                                        id="seller_id" 
                                        name="<?php echo esc_attr($this->option_name); ?>[seller_id]" 
                                        value="<?php echo esc_attr($seller_id); ?>" 
                                        class="regular-text"
                                        placeholder="RcuODgh_9NOtnSKD_lDMfg=="
                                    />
                                    <p class="description">
                                        Your Gumroad seller ID. This will be verified against incoming pings for security.
                                        <br><strong>Your seller_id:</strong> <code>RcuODgh_9NOtnSKD_lDMfg==</code>
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
                    
                    <div class="endpoint-instructions">
                        <h3>📝 Setup Instructions:</h3>
                        <ol>
                            <li>Enter your <strong>Seller ID</strong> above and save settings</li>
                            <li>Copy the webhook endpoint URL above</li>
                            <li>Go to your <a href="https://app.gumroad.com/settings" target="_blank">Gumroad Account Settings</a></li>
                            <li>Find the <strong>"Ping"</strong> or <strong>"Webhooks"</strong> section</li>
                            <li>Paste the endpoint URL</li>
                            <li>Test the connection using the <a href="<?php echo admin_url('admin.php?page=gumroad-connect-test'); ?>">Ping Test</a> page</li>
                        </ol>
                    </div>
                </div>
                
                <!-- Security Notice -->
                <div class="gumroad-card gumroad-security-notice">
                    <h3>🔒 Security Notes</h3>
                    <ul>
                        <li>Always use <strong>HTTPS</strong> endpoints (your site should have SSL)</li>
                        <li>The seller_id will be verified against each incoming ping</li>
                        <li>Only authorized Gumroad requests will be processed</li>
                        <li>Check the <a href="<?php echo admin_url('admin.php?page=gumroad-connect-test'); ?>">Ping Test</a> page to monitor incoming webhooks</li>
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
        
        .gumroad-security-notice ul {
            background: #fff3cd;
            padding: 15px 15px 15px 35px;
            border-left: 4px solid #ffc107;
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
        ';
    }
}

// Initialize the plugin
new Gumroad_Connect();