#!/bin/sh
#
# Run database setup
python3 database/database.py -s

# Run the application
gunicorn app_sec:application --bind 0.0.0.0:8000 --log-file ./gunicorn.log --log-level info

#python3 app_sec.py
