# How to Run Docker Container

This README provides instructions on how to build multiple docker images (if on dev mode jump to [Development mode](#development-mode)).

## Prerequisites

- Docker installed on your machine. To install Docker, follow the instructions on the [Docker website](https://docs.docker.com/get-docker/).

## Building the Docker Images

1. **Clone the Repository (if applicable):**
   ```bash
   git clone [Repository URL]

2. **Navigate to the directory containing the `compose.yml` and run:**
    ```bash
    cd app_sec/ 
    docker compose up -d --build 

# Adding a CA Certificate to Firefox and Chrome

In order to add a CA (Certificate Authority) certificate to Firefox and Chrome, you can follow these steps:

## 1. Prepare Your Certificate

- The CA certificate file (`rootCert.pem`) in the `nginx/certs/` directory.

## 2. Adding the CA Certificate to Firefox

1. Select "Setting" and then "Privacy & Security".
2. Scroll down to the "Certificates" section and click on "View Certificates."
3. In the "Certificate Manager" window, go to the "Authorities" tab.
4. Click the "Import..." button.
5. Locate and select your CA certificate file, then click "Open."
6. Check the option "Trust this CA to identify websites" 
7. Click "OK" to import the certificate.
8. Firefox will ask you to confirm. Click "OK."
9. The CA certificate is now added to Firefox.

## 3. Adding the CA Certificate to Chrome

1. Select "Settings."
2. Scroll down and click on "Advanced" to expand the settings.
3. Under the "Privacy and security" section, click on "Manage certificates."
4. In the "Certificates" window, go to the "Authorities" tab.
5. Click the "Import..." button.
6. Locate and select your CA certificate file, then click "Open."
7. Check the option "Trust this certificate for identifying websites."
8. Click "Next."
9. Choose the option to place the certificate in the "Trusted Root Certification Authorities" store.
10. Click "Next" and then "Finish."
11. Chrome will ask you to confirm. Click "Yes."
12. The CA certificate is now added to Chrome.

That's it! You have successfully added the CA certificate to both Firefox and Chrome, allowing these browsers to trust websites and services signed with this certificate authority.

After this, you can access the application by navigating to https://localhost in your web browser.

## Stopping the Docker Containers

To stop the running containers, you can use the following command:
```bash
docker compose down --rmi all -v --remove-orphans 
```

# Development mode 

## How to run 

1. **Set Up a Virtual Environment**
    ```bash
    python3 -m venv venv
    ```
   This will create a new directory named `venv` which will contain a clean Python environment.

2. **Activate the Virtual Environment**
    - On macOS and Linux:
        ```bash
        source venv/bin/activate
        ```
    Your command prompt should now show the name of the activated virtual environment.

3. **Install Dependencies**

    Install the required packages listed in the `requirements.txt` file.

    ```bash
    pip install -r requirements.txt
    ```
4. **Database options**

   Execute the database script.
   
    ```bash
    python3 database.py
    ```
    With the following flags:
    - `-s` Setup all tables on the database
    - `-c` Show content from every table 
    - `-d` Delete all content from the database

6. **Run Server**
   ```bash
   gunicorn --reload -b 127.0.0.1:8000 app.app_sec:application
   ```

   Now the website should be accessible on the address: http://127.0.0.1:8000 

