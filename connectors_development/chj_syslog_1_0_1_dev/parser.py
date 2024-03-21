from pyparsing import Word, Suppress, Combine, Optional, White, Group, QuotedString, OneOrMore, ZeroOrMore
from pyparsing import alphas, nums, string, restOfLine, lineEnd, printables, Literal

class Parser(object):
    def __init__(self, rfc):
        if rfc == 3164 or rfc  == '3164':
            self.get_rfc3164parser()
        elif rfc == 5424 or rfc == '5424':
            self.get_rfc5424parser()
        else:
            # raise Exception('Unsupported rfc')
            self.get_rfc3164parser()

    def get_rfc3164parser(self):
        # priority
        priority = Suppress('<') + Word(nums) + Suppress('>')

        # timestamp
        month = Word(string.ascii_uppercase, string.ascii_lowercase, exact=3)
        day = Word(nums, min=1, max=2)
        hour = Combine(Word(nums, exact=2) + ':' + Word(nums, exact=2) + ':' + Word(nums, exact=2))

        timestamp = Group(month + day + hour)

        # hostname
        hostname = Word(alphas + nums + "_" + "-" + ".")

        header = Group(timestamp('timestamp') + hostname('hostname'))

        # appname
        appname = Word(alphas + '/-_.()')('appname') + (Suppress('[') + Word(nums)('pid') + Suppress(']')) | \
                  (Word(alphas + '/-_.')('appname') + Suppress(':'))

        # message
        message = Combine(restOfLine + lineEnd)

        # pattern build
        self.__pattern = Optional(priority('priority')) + Optional(header('header')) + Optional(appname) + message('message')

    def get_rfc5424parser(self):
        nilvalue = '-'
        sp = Suppress(White(ws=' ', exact=1))

        priority = Optional(Suppress('<') + Word(nums, min=1, max=3) + Suppress('>'))

        version = Word(nums)

        full_date = Word(nums, exact=4) + '-' + Word(nums, exact=2) + '-' + Word(nums, exact=2)
        partial_time = Word(nums, exact=2) + ':' + Word(nums, exact=2) + ':' + Word(nums, exact=2) + Optional('.') + Word(nums, min=1, max=6)
        time_offset = Literal('Z') | ((Literal('-') | Literal('+')) + Word(nums, exact=2) + ':' + Word(nums, exact=2))
        timestamp = nilvalue | Combine(full_date + 'T' + partial_time + time_offset)

        hostname = nilvalue | Word(printables, min=1, max=255)
        appname = nilvalue | Word(printables, min=1, max=48)
        procid = nilvalue | Word(printables, min=1, max=128)
        msgid = nilvalue | Word(printables, min=1, max=32)

        header = Group(
            priority('priority') + version('version') + sp +
            timestamp('timestamp') + sp + hostname('hostname') + sp +
            appname('appname') + sp + procid('procid') + sp +
            msgid('msgid')
        )
        header.setName('header')

        sd_name = Word(printables, excludeChars='= ]"', min=1, max=32)
        sd_id = sd_name
        param_name = sd_name
        sd_param = Group(param_name('param_name') + Suppress('=') +
                         QuotedString(quoteChar='"', escChar='\\', escQuote='\\')('param_value'))

        sd_element = Group(Suppress('[') + sd_id('sd_id') + ZeroOrMore(sp + sd_param)('sd_params') + Suppress(']'))

        structured_data = (nilvalue | Group(OneOrMore(sd_element)))('sd_element')

        msg = Combine(restOfLine + lineEnd)

        self.__pattern = header('header') + sp + structured_data('sd') + Optional(sp + msg('message'))

    def parse(self, line):
        parsed = self.__pattern.parseString(line)
        return parsed.asDict()
