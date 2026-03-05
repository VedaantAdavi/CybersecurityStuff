import phonenumbers
from phonenumbers import geocoder, carrier

# 1. Parse the phone number (must include '+' and country code)
# Example: +44 20 8366 1177 (UK)
number_str = str(input("Type in a Phonenumber Ex: +9145678489 \n"))
parsed_number = phonenumbers.parse(number_str)

# 2. Get the location description in English
location = geocoder.description_for_number(parsed_number, "en")
print(f"Location: {location}")  # Output: London

# 3. Get the carrier/network provider
service_provider = carrier.name_for_number(parsed_number, "en")
print(f"Carrier: {service_provider}") # Output: BT

# 4. Get the country code
country_code = geocoder.region_code_for_number(parsed_number)
print(f"Country Code: {country_code}") # Output: GB