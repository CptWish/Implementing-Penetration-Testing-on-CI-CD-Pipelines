# 1. Use an official lightweight Python image
FROM python:3.10-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy the local project files into the container
COPY . .

# 4. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 5. Tell Docker what port to expose
EXPOSE 5000

# 6. Define the command to run the app
CMD ["python", "app.py"]
