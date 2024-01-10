import datetime

from rest_framework import status
from rest_framework.response import Response

from bookReview.bookReview.settings import DEFAULT_FROM_EMAIL


def sendHtmlEmail(subject, message, recipient_list, from_email=None):
    if not from_email:
        from_email = DEFAULT_FROM_EMAIL
    from django.core.mail import get_connection
    from django.core.mail import send_mail
    from django.core.mail.message import (
        EmailMessage, EmailMultiAlternatives,
        SafeMIMEText, SafeMIMEMultipart,
        DEFAULT_ATTACHMENT_MIME_TYPE, make_msgid,
        BadHeaderError, forbid_multi_line_headers)
    try:
        connection = get_connection()
        connection.open()
        headers = {'Reply-To': DEFAULT_FROM_EMAIL}
        mail = EmailMultiAlternatives(subject, message, from_email, recipient_list,
                                      connection=connection, headers=headers)
        mail.content_subtype = "html"
        mail.send(fail_silently=True)
        connection.close()
        print('from_email =>', from_email)
        print('recipient_list =>', recipient_list)
        print('subject =>', subject)
        print("email sent")
        return True
    except Exception as e:
        print('Email Exception' + str(e))
        return False


def response_on_exception(e, traceback_traced):
    exc_type, exc_value, exc_traceback = traceback_traced
    traceback_details = {
        'file_name': exc_traceback.tb_frame.f_code.co_filename,
        'line_no': exc_traceback.tb_lineno,
        'name': exc_traceback.tb_frame.f_code.co_name,
        'type': exc_type.__name__,
        'message': str(e),  # or see traceback._some_str()
        'time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return Response({'success': False, 'message': "Server Error", 'traceback': traceback_details},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

