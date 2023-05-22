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
# =================================================
import logging
import time
import re
import os.path
import random
# from ...common.traces import Trace

from .. import scopes, targets
from .CW305 import CW305, CW305_USB
# from ecpy.curves import Curve, Point # type: ignore

from chipwhisperer.logging import *


from typing import Optional, Type, Union


class CW305_Kyber_decaps(CW305):

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
        import chipwhisperer as cw
        self.REG_CRYPT_SS = None
        self.REG_CRYPT_PUBLIC_KEY = None
        self.REG_CRYPT_CIPHERIN = None

        super().__init__()
        # self._clksleeptime = 150 # need lots of idling time
        # Verilog defines file(s):
        # self.default_verilog_defines = 'cw305_defines.v'
        # self.default_verilog_defines_full_path = os.path.dirname(cw.__file__) +  '/../../hardware/victims/cw305_artixtarget/fpga/vivado_examples/ecc_p256_pmul/hdl/' + self.default_verilog_defines
        # 22
        self.registers = 20+11  # number of registers we expect to find
        self.bytecount_size = 7  # 14 # pBYTECNT_SIZE in Verilog
        self.target_name = 'Kyber_decaps'

    def simpleserial_write(self, cmd, data, end=None):
        if cmd == 'c':
            self.loadInput(data)
            # time.sleep(0.05)
            # self.go()
        else:
            raise ValueError("Unkown command {}".format(cmd))

    def loadInput(self, ct):
        if None in [self.REG_CRYPT_CIPHERTEXT_0,
                    self.REG_CRYPT_CIPHERTEXT_1,
                    self.REG_CRYPT_CIPHERTEXT_2,
                    self.REG_CRYPT_CIPHERTEXT_3,
                    self.REG_CRYPT_CIPHERTEXT_4,
                    self.REG_CRYPT_CIPHERTEXT_5,
                    self.REG_CRYPT_CIPHERTEXT_6,
                    self.REG_CRYPT_CIPHERTEXT_7,
                    self.REG_CRYPT_CIPHERTEXT_8,
                    self.REG_CRYPT_CIPHERTEXT_R]:
            target_logger.error(
                "target.REG_CRYPT_CIPHEROUT_n unset. Have you given target a verilog defines file?")
            return
        self.ciphertext = ct

        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_0, ct[0: 128])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_1, ct[128: 256])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_2, ct[256: 384])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_3, ct[384: 512])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_4, ct[512: 640])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_5, ct[640: 768])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_6, ct[768: 896])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_7, ct[896:1024])
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_8, ct[1024:1088])  # 1088

        # ciphertext is available in registers for crypto core to use
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_R, [0x01])

    def readEncryptionKey(self):
        if None in [self.REG_CRYPT_PUBLIC_KEY_0,
                    self.REG_CRYPT_PUBLIC_KEY_1,
                    self.REG_CRYPT_PUBLIC_KEY_2,
                    self.REG_CRYPT_PUBLIC_KEY_3,
                    self.REG_CRYPT_PUBLIC_KEY_4,
                    self.REG_CRYPT_PUBLIC_KEY_5,
                    self.REG_CRYPT_PUBLIC_KEY_6,
                    self.REG_CRYPT_PUBLIC_KEY_7,
                    self.REG_CRYPT_PUBLIC_KEY_8,
                    self.REG_CRYPT_PUBLIC_KEY_9]:
            target_logger.error(
                "target.REG_CRYPT_PUBLIC_KEY_n unset. Have you given target a verilog defines file?")
            return
        # self.key = key

        data = bytearray()
        # key[   0: 128]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_0, 128)
        # key[ 128: 256]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_1, 128)
        # key[ 256: 384]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_2, 128)
        # key[ 384: 512]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_3, 128)
        # key[ 512: 640]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_4, 128)
        # key[ 640: 768]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_5, 128)
        # key[ 768: 896]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_6, 128)
        # key[ 896:1024]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_7, 128)
        # key[1024:1152]
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_8, 128)
        # key[1152:1184]) # 1184
        data += self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_9, 32)

        return data

    def simpleserial_read(self, cmd, pay_len, end='\n', timeout=250, ack=True):
        if cmd == 'r':
            return self.readOutput()
        elif cmd == 'k':
            return self.readEncryptionKey()
        else:
            raise ValueError("Unkown command {}".format(cmd))

    def readOutput(self):
        """"Read output from FPGA"""
        if self.REG_CRYPT_SS is None:
            target_logger.error(
                "target.REG_CRYPT_SS unset. Have you given target a verilog defines file?")
            return

        return self.fpga_read(self.REG_CRYPT_SS, 32)

    def readCiphertext(self):
        if None in [self.REG_CRYPT_CIPHERTEXT_0,
                    self.REG_CRYPT_CIPHERTEXT_1,
                    self.REG_CRYPT_CIPHERTEXT_2,
                    self.REG_CRYPT_CIPHERTEXT_3,
                    self.REG_CRYPT_CIPHERTEXT_4,
                    self.REG_CRYPT_CIPHERTEXT_5,
                    self.REG_CRYPT_CIPHERTEXT_6,
                    self.REG_CRYPT_CIPHERTEXT_7,
                    self.REG_CRYPT_CIPHERTEXT_8]:
            target_logger.error(
                "target.REG_CRYPT_CIPHEROUT_n unset. Have you given target a verilog defines file?")
            return
        data = bytearray()
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_0, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_1, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_2, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_3, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_4, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_5, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_6, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_7, 128)
        data += self.fpga_read(self.REG_CRYPT_CIPHERTEXT_8, 64)  # 1088
        return data

    def reset(self):
        self.fpga_write(self.REG_RST, [0x01])
        time.sleep(0.05)
        self.fpga_write(self.REG_RST, [0x00])

    def go(self):
        # reset the value of ciphertext Ready
        self.fpga_write(self.REG_CRYPT_CIPHERTEXT_R, [0x00])

        super().go()

    def readPKValid(self):
        if (self.REG_CRYPT_PUBLIC_KEY_VALID is None):
            target_logger.error(
                "target.REG_CRYPT_PUBLIC_KEY_VALID unset. Have you given target a verilog defines file?")
            return
        return self.fpga_read(self.REG_CRYPT_PUBLIC_KEY_VALID, 1)[0] == 0x01

    def readSSValid(self):
        if (self.REG_CRYPT_SS_VALID is None):
            target_logger.error(
                "target.REG_CRYPT_SS_VALID unset. Have you given target a verilog defines file?")
            return
        return self.fpga_read(self.REG_CRYPT_SS_VALID, 1)[0] == 0x01
