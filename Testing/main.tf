#############################################
# Terraform Block
#
# Definition:
# The Terraform block is used to configure
# Terraform itself. It specifies the required
# providers, Terraform version, backend
# configuration, and other global settings.
#############################################

terraform {

  required_providers {

    azurerm = {

      source = "hashicorp/azurerm"
      # Provider Source
      # Syntax: source = "<provider_namespace>/<provider_name>"

      version = "~> 4.0"
      # Provider Version
      # Syntax: version = "<provider_version>"
      # "~> 4.0" means use any compatible 4.x version.

    }
  }
}

#############################################
# Provider Block
#
# Definition:
# A Provider is a Terraform plugin that enables
# Terraform to communicate with a cloud platform
# or service (such as Azure, AWS, or GCP) using
# its APIs to create, update, and delete resources.
#############################################

provider "azurerm" { # Syntax: provider "<provider_name>" { }
  features {}        # Mandatory block for azurerm provider

  subscription_id = "YOUR_SUBSCRIPTION_ID" # Syntax: key = value
}

#############################################
# Resource Group
# Definition:
# An Azure Resource Group is a logical container
# used to organize and manage Azure resources
# such as Virtual Machines, VNets, Storage Accounts,
# NSGs, and Load Balancers.
#############################################

resource "azurerm_resource_group" "rg" { # Syntax: resource "<resource_type>" "<local_name>" { }

  name = "demo-rg" # Syntax: key = value
  # Resource Group Name
  location = "East US" # Azure region# Azure Region is the physical
  # geographic location (Azure Data Center)
  # where the resource will be deployed.
  # Examples: East US, West Europe,
  # Central India, South India
}

#############################################
# Virtual Network (VNet)
#
# Definition:
# An Azure Virtual Network (VNet) is a logically
# isolated private network in Azure that enables
# secure communication between Azure resources
# such as Virtual Machines, Subnets, Load Balancers,
# VPN Gateways, and Application Gateways.
#############################################
resource "azurerm_virtual_network" "vnet" { # Syntax: resource "<resource_type>" "<local_name>" { }

  name = "demo-vnet" # VNet Name

  address_space = ["10.0.0.0/16"] # Syntax: List -> ["value1", "value2"]

  location = azurerm_resource_group.rg.location
  # Syntax: <resource_type>.<local_name>.<attribute>
  # Deploy VNet in the same Azure Region as the Resource Group
  resource_group_name = azurerm_resource_group.rg.name
  # Associate VNet with the Resource Group
}



#############################################
# Subnet
#
# Definition:
# A Subnet is a logical subdivision of a Virtual
# Network (VNet). It divides the VNet into smaller
# network segments, allowing better organization,
# security, and IP address management for Azure
# resources.
#############################################

resource "azurerm_subnet" "subnet" { # Syntax: resource "<resource_type>" "<local_name>" { }

  name = "demo-subnet" # Subnet Name

  resource_group_name = azurerm_resource_group.rg.name
  # Resource Group where the VNet exists

  virtual_network_name = azurerm_virtual_network.vnet.name
  # Parent Virtual Network (VNet)

  address_prefixes = ["10.0.1.0/24"] # Subnet CIDR Block
  # IP range assigned to this subnet

}


#############################################
# Storage Account
#
# Definition:
# An Azure Storage Account is a cloud storage
# service that provides secure and scalable
# storage for blobs, files, queues, tables,
# and disks used by Azure resources.
#############################################

resource "azurerm_storage_account" "storage" { # Syntax: resource "<resource_type>" "<local_name>" { }

  name = "demostorageacct12345"
  # Storage Account Name
  # Note: The name must be globally unique
  # (3-24 lowercase letters and numbers only)

  resource_group_name = azurerm_resource_group.rg.name
  # Resource Group where the Storage Account will be created

  location = azurerm_resource_group.rg.location
  # Azure Region

  account_tier = "Standard"
  # Performance Tier
  # Available values: Standard, Premium

  account_replication_type = "LRS"
  # Replication Type
  # LRS = Locally Redundant Storage
  # GRS = Geo-Redundant Storage
  # ZRS = Zone-Redundant Storage
  # GZRS = Geo-Zone-Redundant Storage

}

