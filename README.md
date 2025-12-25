# Gumroad Connect


**If you saved time and money with this project. Support it 😉**

[![Sponsor me](https://img.shields.io/badge/Consider_Supporting_My_Projects_❤-GitHub-d46)](https://github.com/sponsors/sinanisler)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/sinanisler/gumroad-connect)

Connect WordPress with Gumroad webhooks to automatically create user accounts and manage subscriptions.

## Support
On github I only give bug fix support on [issues](https://github.com/sinanisler/gumroad-connect/issues).

If you need paid setup  or training help contact me:  sinan@sinanisler.com
I can kickstart your membership site easily. 😉

> NOTE: This plugin only works with PING/Webhook methodology so I would recommend using this plugin only if you have simple product types. If you will sell recurring products or monthly memberships or yearly memberships and complex products use my other [Gumroad API](https://github.com/sinanisler/gumroad-api) plugin.

## Features

- ✅ **Automatic User Creation** - Creates WordPress users when customers purchase
- ✅ **Product-Specific Roles** - Assign different roles for different products
- ✅ **Custom Email Templates** - Full HTML support with dynamic tags
- ✅ **Secure Endpoints** - Unique hash-based webhook URLs
- ✅ **Comprehensive Logging** - Configurable storage limits (10-1000 entries)
- ✅ **Auto Role Management** - Adds/removes roles based on purchase/cancellation
- ✅ **GitHub Auto-Updates** - Updates directly from repository


## Tutorial Video

<a href="https://www.youtube.com/watch?v=nHEwipRdOxk">
<img width="627" height="357" alt="image" src="https://github.com/user-attachments/assets/eca4cb3b-a9cb-4e4e-92d5-718f7ed54bf9" />
</a>

Screenshots:

<img width="46%" height="auto" alt="image" src="https://github.com/user-attachments/assets/90b7786b-b6af-4af7-8ff6-b87264e68e7e" />
<img width="46%" height="auto" alt="image" src="https://github.com/user-attachments/assets/5f1ca4eb-84fb-42aa-bbf9-7e197f597a91" />



## Installation

1. Upload to `/wp-content/plugins/gumroad-connect`
2. Activate in WordPress admin
3. Go to **Gumroad Connect** > **Settings**
4. Enter your Seller ID
5. Copy webhook URL to Gumroad settings

## Quick Setup

1. Enter Gumroad Seller ID in Settings
2. Enable "Auto Create Users"
3. Configure default roles or product-specific roles
4. Customize email template (optional)
5. Add webhook URL to Gumroad account
6. Test using Ping Test page

## How It Works

1. Customer purchases on Gumroad
2. Webhook sent to WordPress
3. Plugin verifies seller ID
4. User created/updated with assigned roles
5. Welcome email sent with credentials
6. Subscription status tracked for recurring payments
7. Roles removed on cancellation/refund

## Admin Pages

- **Settings** - Configure seller ID, roles, email templates, and storage limits
- **Ping Test** - View incoming webhooks and verify connection
- **User Log** - Monitor user creation and subscription activity
