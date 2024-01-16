import datetime

from rest_framework import status
from rest_framework.response import Response


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

