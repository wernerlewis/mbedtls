#!/usr/bin/env python3
"""Generate test data for bignum functions.

With no arguments, generate all test data. With non-option arguments,
generate only the specified files.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from builtins import ValueError, classmethod, oct, property, staticmethod
import argparse
import itertools
import os
import posixpath
import re
import sys
from typing import Iterable, Iterator, List, Optional, Tuple, TypeVar

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import build_tree
from mbedtls_dev import test_case

T = TypeVar('T') #pylint: disable=invalid-name

def hex_to_int(val):
    return int(val, 16) if val else 0

def quote_str(val):
    return "\"{}\"".format(val)

def to_radix(val, radix, lead_char=""):
    digits = "0123456789abcdef"
    sign = "-" if val < 0 else ""
    if lead_char.startswith("-"):
        lead_char = lead_char[1:]
        sign = "-"
    val = abs(val)
    if radix >= 16 or radix < 2:
        ret = "{}{}{}{}".format(
            sign,
            "0" if (len(hex(val))) % 2 else "",
            lead_char,
            hex(val).replace("0x", "")
            )
    elif radix == 10:
        ret = "{}{}{}".format(sign, lead_char, val)
    else:
        ret_d = []
        while val:
            ret_d.insert(0, digits[val % radix])
            val //= radix
        ret = "{}{}{}".format(sign, lead_char, "".join(ret_d) if ret_d else 0)
    return quote_str(ret)

class BaseTarget:
    """Base target for test case generation.

    Attributes:
        count: Counter for test class.
        desc: Short description of test case.
        func: Function which the class generates tests for.
        gen_file: File to write generated tests to.
        title: Description of the test function/purpose.
    """
    count = 0
    desc = ""
    func = ""
    gen_file = ""
    title = ""

    def __init__(self) -> None:
        type(self).count += 1

    @property
    def args(self) -> List[str]:
        """Create list of arguments for test case."""
        return []

    @property
    def description(self) -> str:
        """Create a numbered test description."""
        return "{} #{} {}".format(self.title, self.count, self.desc)

    def create_test_case(self) -> test_case.TestCase:
        """Generate test case from the current object."""
        tc = test_case.TestCase()
        tc.set_description(self.description)
        tc.set_function(self.func)
        tc.set_arguments(self.args)

        return tc

    @classmethod
    def generate_tests(cls):
        """Generate test cases for the target subclasses."""
        for subclass in sorted(cls.__subclasses__(), key=lambda c: c.__name__):
            yield from subclass.generate_tests()


class BignumTarget(BaseTarget):
    """Target for bignum (mpi) test case generation."""
    gen_file = 'test_suite_mpi.generated'


class BignumOperation(BignumTarget):
    """Common features for test cases covering bignum operations.

    Attributes:
        symb: Symbol used for operation in description.
        input_vals: List of values used to generate test case args.
        input_cases: List of tuples containing test case inputs. This
            can be used to implement specific pairs of inputs.
    """
    symb = ""
    input_vals = [
        "", "0", "7b", "-7b",
        "0000000000000000123", "-0000000000000000123",
        "1230000000000000000", "-1230000000000000000"
    ] # type: List[str]
    input_cases = [] # type: List[Tuple[str, ...]]

    def __init__(self, val_l: str, val_r: str) -> None:
        super().__init__()

        self.arg_l = val_l
        self.arg_r = val_r
        self.int_l = hex_to_int(val_l)
        self.int_r = hex_to_int(val_r)

    @property
    def args(self):
        return [quote_str(self.arg_l), quote_str(self.arg_r), self.result]

    @property
    def description(self):
        desc = self.desc if self.desc else "{} {} {}".format(
            self.val_desc(self.arg_l),
            self.symb,
            self.val_desc(self.arg_r)
        )
        return "{} #{} {}".format(self.title, self.count, desc)

    @property
    def result(self) -> Optional[str]:
        return None

    @staticmethod
    def val_desc(val) -> str:
        """Generate description of the argument val."""
        if val == "":
            return "0 (null)"
        if val == "0":
            return "0 (1 limb)"

        if val[0] == "-":
            tmp = "negative"
            val = val[1:]
        else:
            tmp = "positive"
        if val[0] == "0":
            tmp += " with leading zero limb"
        elif len(val) > 10:
            tmp = "large " + tmp
        return tmp

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, ...]]:
        """Generate value pairs."""
        for pair in list(
                itertools.combinations(cls.input_vals, 2)
            ) + cls.input_cases:
            yield pair

    @classmethod
    def generate_tests(cls) -> Iterator[test_case.TestCase]:
        if cls.func:
            # Generate tests for the current class
            for l_value, r_value in cls.get_value_pairs():
                cur_op = cls(l_value, r_value)
                yield cur_op.create_test_case()
        # Once current class completed, check descendants
        yield from super().generate_tests()


class BignumCmp(BignumOperation):
    """Target for bignum comparison test cases."""
    count = 0
    func = "mbedtls_mpi_cmp_mpi"
    title = "MPI compare"
    input_cases = [
        ("-2", "-3"),
        ("-2", "-2"),
        ("2b4", "2b5"),
        ("2b5", "2b6")
        ]

    def __init__(self, val_l, val_r):
        super().__init__(val_l, val_r)
        self._result = (self.int_l > self.int_r) - (self.int_l < self.int_r)
        self.symb = ["<", "==", ">"][self._result + 1]

    @property
    def result(self):
        return str(self._result)


class BignumCmpAbs(BignumCmp):
    """Target for abs comparison variant."""
    count = 0
    func = "mbedtls_mpi_cmp_abs"
    title = "MPI compare (abs)"

    def __init__(self, val_l, val_r):
        super().__init__(val_l.strip("-"), val_r.strip("-"))


class BignumAdd(BignumOperation):
    """Target for bignum addition test cases."""
    count = 0
    func = "mbedtls_mpi_add_mpi"
    title = "MPI add"
    input_cases = list(itertools.combinations(
        [
            "1c67967269c6", "9cde3",
            "-1c67967269c6", "-9cde3",
        ], 2
    ))

    def __init__(self, val_l, val_r):
        super().__init__(val_l, val_r)
        self.symb = "+"

    @property
    def result(self):
        return quote_str(hex(self.int_l + self.int_r).replace("0x", "", 1))


class BignumReadWrite(BignumTarget):
    """Common features for read/write test cases.

    This will contain
     - Conversion tool for radixes
     - error case attribute

    Generally these will take an input to read,
    and then compare this either with another read
    (with different radix), or write this and
    compare with known input.
    Can generalize test cases to be input only, and
    then create additional info in the class. For
    failure states, these should be added in each child
    class. This may involve:
     - Restricting buffer sizes
     - zeroed data
     - invalid radix
    """
    error_ret = 0
    error_values = {
        "MBEDTLS_ERR_MPI_INVALID_CHARACTER": "Invalid character",
        "MBEDTLS_ERR_MPI_BAD_INPUT_DATA": "Illegal radix",
        "MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL": "Buffer too small"
    }
    input_values = [0, 1, 128, -23, 23, 56125680981752282334141896320372489490613963693556392520816017892111350604111697682705498319512049040516698827829292076808006940873974979584527073481012636016353913462376755556720019831187364993587901952757307830896531678727717924, None]
    # By default we only use radix 16
    # This can be replaced in child classes to add more radix tests
    radices = [10, 16]
    radix = 16

    def __init__(self, val, ret=0, desc="", lead_char="", rad_a=True) -> None:
        """Set A as input, X as output expected."""
        self.input_X = None
        self.desc = " ".join(
            x for x in [
            "base",
            str(self.radix),
            desc if desc else self.gen_desc(val, lead_char)
            ] if x
        )
        if val == None:
            self.input_A = quote_str(lead_char)
            val = 0
            if self.radix == 16 and not rad_a:
                self.input_X = self.input_A
        else:
            self.input_A = to_radix(
                val, self.radix if rad_a else 16, lead_char=lead_char
                )
        if self.input_X is None:
            self.input_X = to_radix(val, 16 if rad_a else self.radix)
        self.error_ret = ret
        if ret:
            self.input_X = quote_str("")
        super().__init__()

    @property
    def description(self):
        if self.error_ret:
            self.desc = "{} ({})".format(self.desc, self.error_desc)
        return super().description

    @property
    def error_desc(self):
        return self.error_values[self.error_ret] if self.error_ret else ""

    def gen_desc(self, val, lead_char):
        input_desc = []
        if val is None:
            input_desc.append("empty string")
        elif val < 0:
            input_desc.append("negative")
        elif val == 0:
            input_desc.append("zero")
        if lead_char and lead_char != "-":
            input_desc += ["leading", lead_char]
        elif lead_char:
            input_desc = ["negative"] + input_desc
        return " ".join(input_desc)

    @classmethod
    def val_buf_size(cls, val):
        """Calculate required buffer size to hold a value."""
        n = abs(val).bit_length()
        if cls.radix >= 4: n >>= 1
        if cls.radix >= 16: n >>= 1
        n += 3 # Null, negative sign and rounding compensation
        n += n & 1 # Ensure n is even for hex
        return n

    @classmethod
    def unique_test_cases(cls):
        """Generate test cases for particular edge cases."""
        return
        yield

    @classmethod
    def fixed_test_cases(cls):
        """Generate radix non-specific edge case tests."""
        return
        yield

    @classmethod
    def generate_tests(cls) -> Iterator[test_case.TestCase]:
        if cls.func:
            # Generate tests for the current class
            # We set current tests radix
            for radix in cls.radices:
                cls.radix = radix
                for input in cls.input_values:
                    cur_op = cls(input)
                    yield cur_op.create_test_case()
                yield from cls.fixed_test_cases()
            yield from cls.unique_test_cases()
        # Once current class completed, check descendants
        yield from super().generate_tests()


class BignumReadString(BignumReadWrite):
    count = 0
    func = "mpi_read_string"
    title = "Read MPI string"

    radix = 0

    def __init__(self, val, ret=0, desc="", lead_char="") -> None:
        super().__init__(val, ret, desc, lead_char)

    @property
    def args(self):
        return [
            str(self.radix), self.input_A,
            self.input_X.upper(), str(self.error_ret)
            ]

    @classmethod
    def fixed_test_cases(cls):
        """Run these on all radices"""
        # Negative zero
        yield cls(0, lead_char="-").create_test_case()
        # Leading zero
        yield cls(56, lead_char="0").create_test_case()
        # Negative leading zero
        yield cls(-34, lead_char="-0").create_test_case()

    @classmethod
    def unique_test_cases(cls):
        """Only run these once"""
        # Invalid radix
        cls.radix = 17
        yield cls(56, ret="MBEDTLS_ERR_MPI_BAD_INPUT_DATA").create_test_case()
        cls.radix = 1
        yield cls(0, ret="MBEDTLS_ERR_MPI_BAD_INPUT_DATA").create_test_case()
        # Radix 15
        cls.radix = 15
        yield cls(29).create_test_case()
        
        # Invalid leading char
        cls.radix = 10
        yield cls(56, lead_char="a", ret="MBEDTLS_ERR_MPI_INVALID_CHARACTER").create_test_case()
        # Few base 2 tests
        cls.radix = 2
        yield cls(0, lead_char="-", desc="negative zero").create_test_case()
        # Leading zero
        yield cls(56, lead_char="0", desc="leading zero").create_test_case()
        yield cls(None, desc="empty hex string").create_test_case()
        yield cls(128).create_test_case()
        yield cls(-23).create_test_case()


class BignumWriteString(BignumReadWrite):
    count = 0
    func = "mpi_write_string"
    title = "Write MPI string"

    def __init__(self, val, ret=0, desc="", lead_char="", buf_size=100):
        self.buf_size = buf_size
        if val is not None and ret == 0 and self.val_buf_size(val) > self.buf_size:
            self.buf_size = 100 * (1 + ( self.val_buf_size(val) // 100 ))
        super().__init__(val, ret, desc, lead_char, rad_a=False)
        """if val is None:
            self.input_X = quote_str(lead_char)
        else:
            self.input_X = to_radix(val, 16, lead_char=lead_char)
        """

    @property
    def args(self):
        return [
            self.input_A, str(self.radix),
            self.input_X.upper(), str(self.buf_size),
            str(self.error_ret)
        ]

    @classmethod
    def generate_small_buf(cls):
        """Generate buffer size, value pairs to test small buffers."""
        # Test up to 4 digits
        for n in range(1, 4):
            max_diff = 0
            max_val = 0
            buf_size = 0
            min_diff = 10
            min_val = 0
            min_buf_size = 100
            for i in range(cls.radix ** (n-1), (cls.radix ** n) -1):
                digits = n + (n % 1) if cls.radix == 16 else n
                diff = cls.val_buf_size(i) - digits
                if diff > max_diff:
                    max_diff = diff
                    max_val = i
                    buf_size = cls.val_buf_size(i)
                if diff < min_diff:
                    min_diff = diff
                    min_val = i
                    min_buf_size = cls.val_buf_size(i)
            yield cls(
                max_val,
                buf_size=buf_size,
                desc="minimal buffer (smallest requirement) {} digit".format(n)
                ).create_test_case()
            yield cls(
                max_val,
                buf_size=buf_size-1,
                ret="MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL",
                desc="under minimal buffer {} digit".format(n)
                ).create_test_case()
            yield cls(
                -min_val,
                buf_size=min_buf_size,
                desc="minimal buffer (largest requirement) {} digit".format(n)
                ).create_test_case()
            yield cls(
                min_val,
                buf_size=min_buf_size-1,
                ret="MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL",
                desc="Under minimal buffer {} digit".format(n)
                ).create_test_case()

    @classmethod
    def fixed_test_cases(cls):
        """Run these on all radices"""
        # Negative zero
        yield cls(0, lead_char="-", desc="negative zero").create_test_case()
        # Leading zero
        yield cls(56, lead_char="0", desc="leading zero").create_test_case()
        # Negative leading zero
        yield cls(-23, lead_char="0", desc="negative leading zero").create_test_case()
        # Just fit - Note buf_size is complex!
        #if cls.radix != 16:
        #    # Run a more complex set of buffer tests on non-16 radix
        #    yield from cls.generate_small_buf()
        #else:
        min_buf_size = cls.val_buf_size(-35)
        yield cls(-35, buf_size=min_buf_size, desc="minimal buffer size").create_test_case() # this fails at 5, passes at 6?
        # too small
        yield cls(-35, ret="MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL", buf_size=min_buf_size-1).create_test_case()

    @classmethod
    def unique_test_cases(cls):
        cls.radix = 2
        yield cls(0, lead_char="-", desc="negative zero").create_test_case()
        # Leading zero
        yield cls(56, lead_char="0", desc="leading zero").create_test_case()
        yield cls(None, desc="empty hex string").create_test_case()
        yield cls(128).create_test_case()
        yield cls(-23).create_test_case()
        cls.radix = 17
        yield cls(56, ret="MBEDTLS_ERR_MPI_BAD_INPUT_DATA").create_test_case()
        cls.radix = 1
        yield cls(0, ret="MBEDTLS_ERR_MPI_BAD_INPUT_DATA").create_test_case()
        # Radix 15
        cls.radix = 15
        yield cls(29).create_test_case()


class TestGenerator:
    """Generate test data."""

    def __init__(self, options) -> None:
        self.test_suite_directory = self.get_option(options, 'directory',
                                                    'tests/suites')

    @staticmethod
    def get_option(options, name: str, default: T) -> T:
        value = getattr(options, name, None)
        return default if value is None else value

    def filename_for(self, basename: str) -> str:
        """The location of the data file with the specified base name."""
        return posixpath.join(self.test_suite_directory, basename + '.data')

    def write_test_data_file(self, basename: str,
                             test_cases: Iterable[test_case.TestCase]) -> None:
        """Write the test cases to a .data file.

        The output file is ``basename + '.data'`` in the test suite directory.
        """
        filename = self.filename_for(basename)
        test_case.write_data_file(filename, test_cases)

    # Note that targets whose names contain 'test_format' have their content
    # validated by `abi_check.py`.
    TARGETS = {
        subclass.gen_file: subclass.generate_tests for subclass in
        BaseTarget.__subclasses__()
    }

    def generate_target(self, name: str) -> None:
        test_cases = self.TARGETS[name]()
        self.write_test_data_file(name, test_cases)

def main(args):
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true',
                        help='List available targets and exit')
    parser.add_argument('--list-for-cmake', action='store_true',
                        help='Print \';\'-separated list of available targets and exit')
    parser.add_argument('--directory', metavar='DIR',
                        help='Output directory (default: tests/suites)')
    parser.add_argument('targets', nargs='*', metavar='TARGET',
                        help='Target file to generate (default: all; "-": none)')
    options = parser.parse_args(args)
    build_tree.chdir_to_root()
    generator = TestGenerator(options)
    if options.list:
        for name in sorted(generator.TARGETS):
            print(generator.filename_for(name))
        return
    # List in a cmake list format (i.e. ';'-separated)
    if options.list_for_cmake:
        print(';'.join(generator.filename_for(name)
                       for name in sorted(generator.TARGETS)), end='')
        return
    if options.targets:
        # Allow "-" as a special case so you can run
        # ``generate_bignum_tests.py - $targets`` and it works uniformly whether
        # ``$targets`` is empty or not.
        options.targets = [os.path.basename(re.sub(r'\.data\Z', r'', target))
                           for target in options.targets
                           if target != '-']
    else:
        options.targets = sorted(generator.TARGETS)
    for target in options.targets:
        generator.generate_target(target)

if __name__ == '__main__':
    main(sys.argv[1:])
