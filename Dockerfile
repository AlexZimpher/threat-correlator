FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install poetry && poetry install && pip install -r requirements-extra.txt
EXPOSE 8501
CMD ["poetry", "run", "streamlit", "run", "src/threatcorrelator/dashboard.py"]
