package example.pwd;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;

public class PasswordTool {
	  
    // Characters to include in the password generation
    private static final String UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()-_=+<>?";

    // Generate a random password based on specified length and criteria
    public static String generatePassword(int length, boolean includeUppercase, boolean includeDigits, boolean includeSpecialChars) {
        StringBuilder password = new StringBuilder(length);
        Random random = new Random();
        
        String characterSet = LOWERCASE_LETTERS;  // Lowercase letters are included by default
        if (includeUppercase) {
            characterSet += UPPERCASE_LETTERS;
        }
        if (includeDigits) {
            characterSet += DIGITS;
        }
        if (includeSpecialChars) {
            characterSet += SPECIAL_CHARACTERS;
        }

        for (int i = 0; i < length; i++) {
            password.append(characterSet.charAt(random.nextInt(characterSet.length())));
        }
        return password.toString();
    }
    
    // Validate the strength of the password
    public static boolean validatePassword(String password) {
        // Define strength requirements: length, uppercase, lowercase, digits, and special characters
        String lengthRegex = ".{8,}"; // Minimum 8 characters
        String uppercaseRegex = ".*[A-Z].*"; // At least one uppercase letter
        String lowercaseRegex = ".*[a-z].*"; // At least one lowercase letter
        String digitRegex = ".*[0-9].*"; // At least one digit
        String specialCharRegex = ".*[!@#$%^&*()-_=+<>?].*"; // At least one special character

        // Check if all requirements are met
        return Pattern.matches(lengthRegex, password) &&
               Pattern.matches(uppercaseRegex, password) &&
               Pattern.matches(lowercaseRegex, password) &&
               Pattern.matches(digitRegex, password) &&
               Pattern.matches(specialCharRegex, password);
    }
    
    // Check if password is common (exists in the common_passwords.txt file)
    public static boolean isCommonPassword(String password) throws IOException {
        List<String> commonPasswords = Files.readAllLines(new File("common_pwds.txt").toPath());
        return commonPasswords.contains(password);
    }

	public static void main(String[] args) {
		 try {
	            // Step 1: Generate a random password
	            String generatedPassword = generatePassword(12, true, true, true);
	            System.out.println("Generated Password: " + generatedPassword);
	            
	            // Step 2: Validate the password strength
	            boolean isStrong = validatePassword(generatedPassword);
	            System.out.println("Is Password Strong? " + (isStrong ? "Yes" : "No"));
	            
	            // Step 3: Check if the password is commonly used
	            boolean isCommon = isCommonPassword(generatedPassword);
	            System.out.println("Is Password Common? " + (isCommon ? "Yes" : "No"));
	            
	            // Final Output
	            if (isStrong && !isCommon) {
	                System.out.println("The generated password is strong and secure.");
	            } else if (isCommon) {
	                System.out.println("Warning: The password is too common and should not be used.");
	            } else {
	                System.out.println("The password does not meet strength requirements.");
	            }
	            
	        } catch (IOException e) {
	            System.err.println("Error reading common passwords file: " + e.getMessage());
	        }// TODO Auto-generated method stub

	}

}
