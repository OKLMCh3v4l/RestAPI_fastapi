Prerequired:
  apt install python3 python3-pip
  pip install fastapi uvicorn python-jose pydantic

Run the app with "uvicorn":
  uvicorn api_fastapi_v5:app --reload

Base api location:
  http://127.0.0.1:8000
  # Swagger located at: http://127.0.0.1:8000/docs#/
