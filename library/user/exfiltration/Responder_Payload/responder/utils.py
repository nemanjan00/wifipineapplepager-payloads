# Compatibility shim for legacy Responder imports
# DO NOT REMOVE — required by Responder.py

from packets import *
from odict import *
from Report import *
import logging
import socket
import struct
import sys
import os
import time

def banner():
    try:
        from Responder import __doc__
        print(__doc__)
    except Exception:
        print("Responder")

def InitResponder(*args, **kwargs):
    pass
