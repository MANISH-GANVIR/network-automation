provider "azurerm" { # Syntax: provider "<provider_name>" { }
  features {}        # Mandatory block for azurerm provider

  #subscription_id = "YOUR_SUBSCRIPTION_ID" # Syntax: key = value
}
resource "azurerm_resource_group" "rg" {
  name     = "demo-rg"
  location = "East US"
}

resource "azurerm_virtual_network" "vnet" {
  name                = "demo-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "demo-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}