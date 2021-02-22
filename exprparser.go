package main

import (
	"bufio"
	"bytes"
	"io"
)

type Token int

const eof = rune(0)

const (
	ILLEGAL Token = iota
	EOF
	WS

	IDENT

	ASTERISK
	COMMA
	SEMICOLON
	GT
	LT
	GET
	LET
	EQ
	PLUS
	MINUS
	DIVISION
	R_PAREN
	L_PAREN
	PERIOD
)

type Scanner struct {
	r *bufio.Reader
}

func newScanner(r io.Reader) *Scanner {
	return &Scanner{r: bufio.NewReader(r)}
}

func (s *Scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}

	return ch
}

func isWhiteSpace(ch rune) bool {
	if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
		return true
	}
	return false
}

func isLetter(ch rune) bool {
	if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
		return true
	}
	return false
}

func isDigit(ch rune) bool {
	if ch >= '0' && ch <= '9' {
		return true
	}
	return false
}

func isNumber(chs []rune) bool {
	var dotCounter int
	for i := range chs {
		if chs[i] == '.' {
			dotCounter++
			if dotCounter > 1 {
				return false
			}
			continue
		}

		if !isDigit(chs[i]) {
			return false
		}
	}

	return true
}

func (s *Scanner) unread() { _ = s.r.UnreadRune() }

func (s *Scanner) scanWhitespace() (tok Token, lit string) {
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isWhiteSpace(ch) {
			s.unread()
			break
		} else {
			buf.WriteRune(ch)
		}
	}

	return WS, buf.String()
}

func (s *Scanner) scanIdent() (tok Token, lit string) {
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isLetter(ch) && !isDigit(ch) && ch != '_' {
			s.unread()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}

	return IDENT, buf.String()
}

func (s *Scanner) scan() (tok Token, lit string) {
	ch := s.read()

	if isWhiteSpace(ch) {
		s.unread()
		return s.scanWhitespace()
	} else if isLetter(ch) {
		s.unread()
		return s.scanIdent()
	}

	switch ch {
	case eof:
		return EOF, string(ch)
	case '*':
		return ASTERISK, string(ch)
	case '+':
		return PLUS, string(ch)
	case '-':
		return MINUS, string(ch)
	case '/':
		return ASTERISK, string(ch)
	case '(':
		return R_PAREN, string(ch)
	case ')':
		return L_PAREN, string(ch)
	case ',':
		return ASTERISK, string(ch)
	case ';':
		return ASTERISK, string(ch)
	case '<':
		return LT, string(ch)
	case '>':
		return GT, string(ch)
	case '.':
		return PERIOD, string(ch)
	}

	return ILLEGAL, string(ch)
}

type Parser struct {
	s   *Scanner
	buf struct {
		tok Token
		lit string
		n   int
	}
}

func newParser(r io.Reader) *Parser {
	return &Parser{s: newScanner(r)}
}

func (p *Parser) scan() (tok Token, lit string) {
	if p.buf.n != 0 {
		p.buf.n = 0
		return p.buf.tok, p.buf.lit
	}

	tok, lit = p.s.scan()
	p.buf.tok, p.buf.lit = tok, lit

	return
}

func (p *Parser) unscan() { p.buf.n = 1 }

type ASTNode struct {
	isIdentifier bool
	isLiteral    bool
	isIllegal    bool
	isEOF        bool
	isWS         bool
	children     []*ASTNode
	value        interface{}
}
