# PIM Role Advisor

An AI-powered FastAPI application that provides intelligent Microsoft Entra ID role recommendations based on specific tasks. The application integrates with Azure OpenAI and Microsoft Graph API to analyze role permissions and suggest the least privileged role required for any given task.

## Features

- **AI-Powered Recommendations**: Uses Azure OpenAI to provide contextual role suggestions
- **Microsoft Graph Integration**: Fetches live role definitions and PIM groups from your tenant
- **Device Code Flow Authentication**: Secure authentication using Azure AD Device Code Flow
- **Least Privilege Focus**: Always recommends the minimum required permissions
- **Detailed Analysis**: Provides comprehensive explanations for each recommendation
- **Modern Web Interface**: Clean, responsive HTML interface

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

1. Clone this repository:
   ```powershell
   git clone <repository-url>
   cd pim_role_advisor
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
