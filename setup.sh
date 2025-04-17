#!/bin/bash

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH
    echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
    eval "$(/opt/homebrew/bin/brew shellenv)"
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    brew install node
fi

# Check if required Python packages are installed
echo "Installing Python dependencies..."
pip install pandas matplotlib seaborn

# Create required directories
echo "Creating required directories..."
mkdir -p uploads
mkdir -p public

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

echo "Setup complete! Starting the server..."
# Start the server
npm run dev 