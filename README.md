# Online Shop Project - DETI Memorabilia
The shop should be the one-stop destination for DETI memorabilia at the University of Aveiro! It should offer a wide range of items, from mugs and cups to t-shirts, hoodies, stamps, stickers, magnets, pins, whatever allows allowing you to proudly showcase your affiliation with the Department of Electronics, Telecommunications, and Informatics.

## Shop Functionalities

1. **User Management:**
   - User registration and login
   - User profiles
   - Password management (change)
   - User roles and permissions (admin, customer)

2. **Product Catalog:**
   - Product listings with details (name, description, price, images)
   - Product categories and filters
   - Product search functionality

3. **Shopping Cart:**
   - Cart management (add, remove, update items)
   - Cart total calculation

4. **Checkout Process:**
   - Shipping and billing information collection

5. **Inventory Management:**
   - Tracking product availability (in-stock, out-of-stock)
   - Managing product quantities

6. **Reviews and Ratings:**
   - Allow customers to rate and review products
   - Display average ratings and reviews

### To Do
   - Save cart for later or wish list
   - Payment processing (credit card, PayPal, etc.)
   - Order confirmation and receipt generation
   - View and track past orders
   - Reorder from order history

## Features 

### 1. Authentication and Session Management

- Implement Multi-factor Authentication (MFA) using methods like TOTP, OAuth 2.0 + OIDC, or FIDO/FIDO2.
- Strengthen password policies (e.g., minimum length, complexity requirements).
- Secure session management (e.g., secure cookies, session timeouts).

### 2. Input Validation and Output Encoding

- Implement robust input validation to prevent injection attacks (e.g., SQL injection, Cross-site Scripting).
- Use output encoding to prevent Cross-site Scripting (XSS).

### 3. Data Protection

- Encrypt sensitive data both in transit (using HTTPS) and at rest (in databases).

### 4. Error Handling and Logging

- Ensure secure and informative error handling that doesn’t reveal sensitive information.

### 5. System Robustness

- Harden servers and databases against attacks.

### 6. File and Resource Handling

- Implement secure file upload handling (e.g., file type restrictions, size limits).

### 9. API and Web Service Security

- Use tokens (e.g., JWT) for secure API authentication.

## Authors 
   - Afonso Baixo
   - Paulo Macedo
   - Michael Cerqueira
   - Vasco Rodrigues
