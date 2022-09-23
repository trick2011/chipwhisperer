#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2015-2020, NewAE Technology Inc
# All rights reserved.
#
# Find this and more at newae.com - this file is part of the chipwhisperer
# project, http://www.chipwhisperer.com . ChipWhisperer is a registered
# trademark of NewAE Technology Inc in the US & Europe.
#
#    This file is part of chipwhisperer.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#=================================================
import logging
import time
import re
import os.path
import random
# from ...common.traces import Trace

from ...capture import scopes, targets
from .CW305 import CW305, CW305_USB
# from ecpy.curves import Curve, Point # type: ignore

from chipwhisperer.logging import *



from typing import Optional, Type, Union

class CW305_AES(CW305):

    """CW305 target object for Kyber target.

    This class contains the public API for the CW305 hardware.
    To connect to the CW305, the easiest method is::

        import chipwhisperer as cw
        scope = cw.scope()
        target = cw.target(scope, cw.targets.CW305_Kyber,
                           bsfile=<valid FPGA bitstream file>)

    Note that connecting to the CW305_Kyber includes programming the CW305 FPGA.
    For more help about CW305 settings, try help() on this CW305 submodule:

       * target.pll
    """


    _name = "ChipWhisperer CW305 (Artix-7)"


    def __init__(self):
        self.REG_OPERATION = None

        super().__init__()
        # self._clksleeptime = 150 # need lots of idling time
        # Verilog defines file(s):
        # self.default_verilog_defines = 'cw305_defines.v'
        # self.default_verilog_defines_full_path = os.path.dirname(cw.__file__) +  '/../../hardware/victims/cw305_artixtarget/fpga/vivado_examples/ecc_p256_pmul/hdl/' + self.default_verilog_defines
        # 22
        self.registers = 13 #11 # number of registers we expect to find
        self.bytecount_size = 7 # 14 # pBYTECNT_SIZE in Verilog
        

    def simpleserial_read(self, cmd, pay_len, end='\n', timeout=250, ack=True):
        """Read data from target

        Mimics simpleserial protocol of serial based targets

        Args:
            cmd (str): Command to ues. Only accepts 'r' for now.
            pay_len: Unused
            end: Unused
            timeout: Unused
            ack: Unused

        Returns: Value from Crypto output register

        .. versionadded:: 5.1
            Added simpleserial_read to CW305
        """
        if cmd == "r":
            return self.readOutput()
        elif cmd == "o":
            return self.fpga_read(self.REG_OPERATION, 1)
        else:
            raise ValueError("Unknown command {}".format(cmd))

    def simpleserial_write(self, cmd, data, end=None):
        """Write data to target.

        Mimics simpleserial protocol of serial based targets.

        Args:
            cmd (str): Command to use. Target supports 'p' (write plaintext),
                and 'k' (write key).
            data (bytearray): Data to write to target
            end: Unused

        Raises:
            ValueError: Unknown command

        .. versionadded:: 5.1
            Added simpleserial_write to CW305
        """
        if cmd == 'p':
            self.loadInput(data)
            self.go()
        elif cmd == 'k':
            self.loadEncryptionKey(data)
        elif cmd == 'o':
            self.fpga_write(self.REG_OPERATION, data)
        else:
            raise ValueError("Unknown command {}".format(cmd))