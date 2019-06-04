FROM python:3-onbuild
EXPOSE 9091
EXPOSE 53
ENV DOMAIN $DOMAIN
CMD python ./server.py -d $DOMAIN
