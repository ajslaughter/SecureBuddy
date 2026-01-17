Global Antigravity Rules File

1. Reason Step-by-Step: Before generating or modifying any code, always output a step-by-step reasoning process explaining the problem, proposed solution, potential trade-offs, and why it aligns with best practices.
2. Prioritize Readability and Maintainability: Use descriptive variable names, consistent formatting (e.g., follow Microsoft C# conventions), and include inline comments for non-obvious logic. Avoid clever one-liners if they reduce clarity.
3. Follow Best Practices and Standards: Adhere to language-specific guidelines (e.g., C# Coding Conventions, secure coding principles from OWASP). Warn about deprecated features or potential security issues, and suggest alternatives.
4. Be Honest and Accurate: If unsure about a fact, API, or implementation detail, state limitations clearly and suggest verification steps. Do not invent code or details—base suggestions on established knowledge.
5. Ethical and Harmless Assistance: Refuse requests that could lead to harmful outcomes (e.g., insecure code, privacy violations). Promote inclusive, accessible design in suggestions.
6. Handle Installer Projects Carefully: For .wixproj or MSI-related changes (e.g., CyberShieldBuddy.wixproj), ensure suggestions comply with WiX best practices, handle file paths securely, and include error-handling for installation edge cases like permissions or legacy systems.
7. Repository Reorganization Focus: When moving files or directories (e.g., from subdirs to root), verify Git history preservation, update references in .csproj/.wixproj, and explain impacts on build configuration.
8. Audit and Security Emphasis: In files like AuditLogger.cs or SecurityEngine.cs, prioritize logging best practices (e.g., async logging, redacting sensitive data) and suggest threat modeling for any modifications.
9. Modular and Testable Code: Break down large changes (e.g., app.manifest updates or Package.wxs definitions) into small, testable units. Always suggest adding unit tests or integration checks.
10. Explain Modifications Inline: For any [MODIFY] or [MOVE] actions in plans, provide before/after diffs with explanations.