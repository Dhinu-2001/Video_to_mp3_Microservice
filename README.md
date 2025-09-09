### **Video to MP3 Converter Microservice**

This project is a hands-on demonstration of a microservice architecture and distributed system designed to convert video files to MP3 audio. The application uses a message queue to manage the communication and workflow between different services.

-----

### **Features**

  * **Video to MP3 Conversion:** Converts uploaded video files into MP3 audio files.
  * **Microservice Architecture:** The application is split into multiple, independently deployable services.
  * **Asynchronous Processing:** Utilizes a message queue (**RabbitMQ**) to handle tasks, preventing the main service from being blocked.
  * **Email Notification:** Notifies the client via email when the conversion is complete.
  * **Secure Downloads:** Allows clients to download the converted MP3 using a unique ID and a JSON Web Token (**JWT**).

-----

### **Technologies Used**

  * **Python:** The primary programming language for the services.
  * **RabbitMQ:** A message broker for asynchronous communication.
  * **MongoDB:** A NoSQL database used to store the video and MP3 files.
  * **Docker:** Used for containerizing the application services.
  * **Kubernetes:** An open-source system for automating deployment, scaling, and management of containerized applications.
  * **MySQL:** A relational database.

-----

### **Application Flow**

1.  A user uploads a video file to the **Gateway** service.
2.  The **Gateway** stores the video in **MongoDB** and sends a message to a **RabbitMQ** queue.
3.  The **Video to MP3 Converter** service consumes the message, retrieves the video from **MongoDB**, and converts it to an MP3.
4.  The converted MP3 is stored back in **MongoDB**.
5.  The **Converter** service sends a new message to **RabbitMQ** for the **Notification** service.
6.  The **Notification** service consumes this message and sends a download email to the user.
7.  The user uses a unique ID and a JWT to request the MP3 from the **Gateway**.
8.  The **Gateway** retrieves the MP3 from **MongoDB** and serves it to the user.

-----

### **Setup Instructions**

Follow these steps to set up and run the Video to MP3 Converter microservice project.

#### **Prerequisites**

You will need the following software installed on your machine:

  * **Docker** and **Docker Compose**
  * **Python 3.x**
  * **Git**

-----

#### **Installation & Running**

1.  **Clone the repository:**

    ```bash
    git clone [your-repository-url]
    cd [your-repository-name]
    ```

2.  **Start the services:**
    The project uses Docker for containerization. Use Docker Compose to launch all the microservices, the message queue (RabbitMQ), and the databases (MongoDB, MySQL).

    ```bash
    docker-compose up --build
    ```

    This command will build the Docker images for each service and start the containers.

3.  **(Optional) Kubernetes:**
    If you plan to deploy the application on a Kubernetes cluster, you will need to apply the provided YAML configuration files using `kubectl`.
