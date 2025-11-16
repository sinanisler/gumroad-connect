# Gumroad Connect

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/sinanisler/gumroad-connect)
[![Sponsor me](https://img.shields.io/badge/Sponsor_The_Project_❤-GitHub-d46)](https://github.com/sponsors/sinanisler)


Connect your WordPress site with Gumroad PING WEBHOOK to automatically create user accounts when customers make a purchase.


## Tutorial Video

<a href="https://www.youtube.com/watch?v=nHEwipRdOxk">
<img width="627" height="357" alt="image" src="https://github.com/user-attachments/assets/eca4cb3b-a9cb-4e4e-92d5-718f7ed54bf9" />
</a>




## Features

✅ **Automatic User Creation** - Creates WordPress users automatically when customers purchase your Gumroad products

✅ **Custom Role Assignment** - Assigns custom "Paid Member" role plus any additional roles you choose

✅ **Email Notifications** - Sends welcome emails with login credentials to new users

✅ **Webhook Integration** - Real-time processing of Gumroad purchases via webhooks

✅ **Security Verification** - Validates seller ID to ensure requests are legitimate

✅ **Comprehensive Logging** - Tracks all webhook pings and user creation activities with pagination

✅ **Existing User Handling** - Adds roles to existing users instead of creating duplicates

✅ **Customizable Emails** - Configure welcome email subject and message

✅ **Test Mode Support** - Built-in ping test page to verify your webhook setup

✅ **User Metadata** - Stores Gumroad purchase information (sale ID, product name, purchase date)

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`
2. Activate the plugin through the WordPress admin panel
3. Navigate to **Gumroad Connect** > **Settings**
4. Enter your Gumroad Seller ID
5. Copy the webhook URL and add it to your Gumroad account settings

## Quick Setup

1. **Get Your Seller ID** - Find it in your Gumroad account settings
2. **Configure Plugin** - Paste your Seller ID in plugin settings
3. **Enable User Creation** - Check "Auto Create Users" option
4. **Select Roles** - Choose which roles to assign (recommended: Paid Member + Subscriber)
5. **Add Webhook** - Copy the ping endpoint URL to your Gumroad account
6. **Test Connection** - Use the Ping Test page to verify everything works

## How It Works

1. Customer purchases your product on Gumroad
2. Gumroad sends webhook notification to your WordPress site
3. Plugin verifies the seller ID for security
4. WordPress user account is created with customer's email
5. Selected roles are assigned to the user
6. Welcome email with login credentials is sent automatically
7. Purchase details are logged for your records

## Admin Pages

- **Settings** - Configure seller ID, user roles, and email templates
- **Ping Test** - View incoming webhooks and test your connection
- **User Log** - Monitor all user creation activities (last 100 entries with pagination)
