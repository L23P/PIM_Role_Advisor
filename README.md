# PIM Role Advisor - Advanced RBAC Analytics for Entra ID

🛡️ **Comprehensive Role-Based Access Control Analysis and Optimization Tool**

The PIM Role Advisor is an advanced analytics platform that scans your Entra ID environment to identify security risks, over-privileged users, and optimization opportunities. It combines AI-powered insights with comprehensive data analysis to provide actionable recommendations for improving your organization's RBAC posture.

## 🚀 Key Features

### 📊 Comprehensive Environment Analysis
- **Complete Inventory**: Scans all users, groups, roles, and assignments in your Entra ID
- **Risk Assessment**: Identifies high, medium, and low-risk users based on multiple factors
- **Permission Analytics**: Analyzes active vs. eligible role assignments and PIM adoption
- **Orphaned Permissions**: Detects role assignments for non-existent principals

### 🤖 AI-Powered Recommendations
- **Role Optimization**: Intelligent suggestions for least-privilege role assignments
- **Group Consolidation**: Identifies opportunities to optimize group structures
- **Security Improvements**: Highlights potential security vulnerabilities and misconfigurations
- **Best Practices**: Provides guidance aligned with Microsoft security recommendations

### 📈 Advanced Analytics Dashboard
- **Interactive Web Interface**: Modern, responsive dashboard for exploring analysis results
- **Dark/Light Mode Toggle**: User-selectable interface theme with persistent preferences
- **Easy Navigation**: Intuitive controls including back button for seamless user experience
- **Real-time Analysis**: Background processing with status updates
- **Detailed Drill-down**: Comprehensive views of users, groups, and recommendations
- **Export Capabilities**: Generate detailed reports for stakeholders and auditors

### 🔍 Risk Detection Engine
- **Over-privileged Users**: Identifies users with excessive permissions
- **Role-Department Mismatches**: Detects potential misalignment between job function and permissions
- **Stale Accounts**: Flags users without recent sign-in activity
- **High-privilege Active Roles**: Recommends converting to eligible-only assignments

## 💻 User Interface Features

### 🎨 Adaptive Theming
- **Dark/Light Mode**: Toggle between dark and light themes based on your preference
- **Persistent Settings**: Your theme preference is saved locally between sessions
- **System Preference Detection**: Automatically adopts your operating system's theme preference

### 📱 Responsive Design
- **Mobile-Friendly**: Optimized for both desktop and mobile devices
- **Accessible Controls**: Large, clear buttons and intuitive navigation
- **High Contrast Elements**: Carefully designed for readability in all lighting conditions

### 📊 Visual Data Presentation
- **Interactive Metrics**: Clear, concise presentation of key statistics
- **Tabbed Navigation**: Easily switch between different views of analysis data
- **Optimized Tables**: Responsive tables with sorting and filtering capabilities
- **Intuitive Icons**: Visual indicators for risk levels and recommendation categories

## UI Features

### Dark Mode / Light Mode
PIM Role Advisor includes a toggle for switching between dark and light modes. The preference is saved in local storage, so it persists across sessions.

To use:
- Click the moon/sun icon in the top right corner of any page
- The icon changes to reflect the current mode (moon = switch to dark mode, sun = switch to light mode)
- The application automatically detects your system preference for first-time users

### Navigation
- **Back Button**: On analysis pages, use the back button in the top left corner to return to the home page
- **Tab Navigation**: Switch between different views of analysis data using the tabbed interface

## 🏗️ Architecture

```
PIM Role Advisor/
├── 🌐 Web Interface (FastAPI)
│   ├── main.py              # Main application and AI chat
│   ├── analysis_routes.py   # Analysis API endpoints
│   └── templates/           # HTML templates
├── 🔍 Analysis Engine
│   ├── pim_analyzer.py      # Core analysis logic
│   └── analyze_pim.py       # Standalone CLI tool
├── 🔐 Authentication
│   └── auth.py              # Entra ID authentication
└── 🧪 Testing Tools
    └── populate_entra_group_&_users.py  # Test environment setup
```

## Prerequisites

This guide assumes you have:
- Basic knowledge of Azure Management (subscriptions, resource groups, etc.)
- An Azure subscription with appropriate permissions
- Access to Azure OpenAI Service
- Administrative access to an Azure tenant for app registration

## Setup Instructions

### 1. Azure App Registration

1. Navigate to the [Azure Portal](https://portal.azure.com)
2. Go to **Azure Active Directory** > **App registrations** > **New registration**
3. Configure the registration:
   - **Name**: `PIM Role Advisor`
   - **Supported account types**: `Accounts in this organizational directory only`
   - **Redirect URI**: Leave blank (we'll use Device Code Flow)
4. Click **Register**

After registration:
1. Go to **API permissions** and add the following Microsoft Graph permissions:
   - `Directory.Read.All` (Application)
   - `Group.Read.All` (Application)
   - `RoleManagement.Read.All` (Application)
2. Click **Grant admin consent** for your organization
3. Go to **Certificates & secrets** > **New client secret**
   - **Description**: `PIM Role Advisor Secret`
   - **Expires**: Choose appropriate duration
   - **Copy the secret value** (you won't see it again)
4. Note down the **Application (client) ID** and **Directory (tenant) ID** from the Overview page

### 2. Azure OpenAI Setup

1. Navigate to [Azure AI Studio](https://ai.azure.com)
2. Create or select an existing Azure OpenAI resource
3. Deploy a model:
   - Go to **Deployments** > **Create new deployment**
   - **Model**: Choose `gpt-4` or `gpt-4-turbo` (recommended)
   - **Deployment name**: `pim-advisor` (or your preferred name)
   - **Version**: Latest available
4. Note down:
   - **Endpoint URL** (from the resource overview)
   - **API Key** (from Keys and Endpoint section)
   - **Deployment name** (what you named your model deployment)

### 3. Environment Configuration

1. Clone this repository:   ```powershell
   git clone https://github.com/L23P/PIM_Role_Advisor.git
   cd PIM_Role_Advisor
   ```

2. Create a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root with the following variables:
   ```env
   # Azure AD App Registration
   AZURE_CLIENT_ID=your-application-client-id
   AZURE_CLIENT_SECRET=your-client-secret
   AZURE_TENANT_ID=your-tenant-id

   # Azure OpenAI Configuration
   AZURE_OPENAI_API_KEY=your-openai-api-key
   AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com/
   AZURE_OPENAI_DEPLOYMENT=your-deployment-name
   ```

### 4. Running the Application

1. Ensure your virtual environment is activated:
   ```powershell
   .\venv\Scripts\activate
   ```

2. Start the application:
   ```powershell
   python main.py
   ```

3. Open your browser and navigate to `http://127.0.0.1:8000`

## Usage

1. **Enter Your Question**: Type a task-related question (e.g., "reset a user's password", "create a new security group")

2. **Authentication**: On first use, you'll be prompted to authenticate using Device Code Flow:
   - A code will be displayed
   - Visit the provided URL and enter the code
   - Sign in with an account that has permissions to read directory information

3. **Get Recommendations**: The AI will analyze your question against available roles and provide:
   - The least privileged role required
   - Detailed explanation of permissions
   - Alternative roles considered (and why they weren't recommended)
   - Microsoft documentation references
   - Available PIM groups in your environment

## Example Questions

- "Create a new user account"
- "Reset a user's password"
- "Assign licenses to users"
- "Create security groups"
- "Manage conditional access policies"
- "View audit logs"
- "Manage application registrations"

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │───▶│   FastAPI App    │───▶│ Microsoft Graph │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                               ▼
                       ┌──────────────────┐
                       │  Azure OpenAI    │
                       └──────────────────┘
```

## Files Structure

- `main.py` - Main FastAPI application with routes and logic
- `auth.py` - MSAL authentication handling for Device Code Flow
- `templates/index.html` - Web interface template
- `.env` - Environment variables (create this file)
- `requirements.txt` - Python dependencies

## Troubleshooting

### Authentication Issues
- Ensure app registration has correct API permissions
- Verify admin consent has been granted
- Check that client secret hasn't expired

### API Errors
- Verify Azure OpenAI endpoint and API key are correct
- Ensure the deployment name matches exactly
- Check that your OpenAI resource has sufficient quota

### Permission Errors
- Ensure the authenticated user has directory read permissions
- Verify the app registration has the required Graph API permissions

## Security Considerations

- Store sensitive information in `.env` file (never commit to version control)
- Regularly rotate client secrets
- Monitor API usage and costs
- Review and audit role assignments regularly
- Use least privilege principles for the app registration itself

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review Azure OpenAI and Microsoft Graph documentation
3. Open an issue in this repository with detailed error information
