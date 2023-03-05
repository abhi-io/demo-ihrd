# -*- coding: utf-8 -*-
from datetime import datetime

FORMAT = "%Y-%m-%d %H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"


def calculate_time_difference(start_date, end_date):

    time_difference = datetime.strptime(start_date, FORMAT) - datetime.strptime(
        end_date, FORMAT
    )
    days = time_difference.days
    seconds = time_difference.seconds
    day_hours = days * 24
    day_seconds = day_hours * 3600
    total_seconds = day_seconds + seconds
    return total_seconds


def get_timestamp():
    now_time = datetime.now()
    time = now_time.strftime(FORMAT)
    return time


def convert_str_time(time):
    new_time = datetime.strptime(time, FORMAT)
    return new_time


def convert_to_str_time(time):
    new_time = datetime.strftime(time, FORMAT)
    return new_time


def convert_str_date(date):
    if date:
        new_date = datetime.strptime(date, DATE_FORMAT)
        return new_date
    return None
