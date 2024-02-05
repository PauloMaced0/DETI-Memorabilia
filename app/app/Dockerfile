FROM frolvlad/alpine-python3

WORKDIR /cherrypy_app

COPY ./ ./

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
