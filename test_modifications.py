#!/usr/bin/env python3
"""
Test script to verify the modifications to the banana disease detection app.
This script tests the separation of banana types and diseases.
"""

import sys
import os

# Add the flask directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'flask'))

# Import the modified app
from app import banana_types, disease_info

def test_banana_types():
    """Test that banana types are properly defined"""
    expected_types = ["_bhimkol", "_jahaji_fruit", "_jahaji_leaf", "_jahaji_stem", "_kachkol_fruit", "_malbhog_fruit", "_malbhog_leaf"]
    
    print("Testing banana types...")
    print(f"Defined banana types: {banana_types}")
    
    # Check that all expected types are in the banana_types list
    for type_name in expected_types:
        assert type_name in banana_types, f"Expected type {type_name} not found in banana_types"
    
    print("✅ All banana types are correctly defined")

def test_disease_info():
    """Test that disease info properly distinguishes types from diseases"""
    print("\nTesting disease info...")
    
    # Check that banana types have the is_type flag set to True
    for type_name in banana_types:
        info = disease_info.get(type_name, {})
        assert info.get("is_type", False) == True, f"Type {type_name} should have is_type=True"
        print(f"✅ {type_name} correctly marked as type")
    
    # Check that diseases don't have the is_type flag or have it set to False
    disease_examples = ["potassium_deficiency", "_bacterial_softrot", "_black_sigatoka"]
    for disease_name in disease_examples:
        info = disease_info.get(disease_name, {})
        assert info.get("is_type", False) == False, f"Disease {disease_name} should not be marked as type"
        print(f"✅ {disease_name} correctly marked as disease")

def test_type_info_structure():
    """Test that banana types have the correct structure (no cause, effects, remedies)"""
    print("\nTesting type info structure...")
    
    for type_name in banana_types:
        info = disease_info.get(type_name, {})
        
        # Types should have empty cause and effects
        assert info.get("cause", "") == "", f"Type {type_name} should have empty cause"
        assert info.get("effects", "") == "", f"Type {type_name} should have empty effects"
        assert info.get("remedies", []) == [], f"Type {type_name} should have empty remedies"
        assert info.get("medicines", []) == [], f"Type {type_name} should have empty medicines"
        
        print(f"✅ {type_name} has correct structure for type information")

if __name__ == "__main__":
    print("Running tests for banana disease detection app modifications...")
    
    try:
        test_banana_types()
        test_disease_info()
        test_type_info_structure()
        
        print("\n🎉 All tests passed! The modifications are working correctly.")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)