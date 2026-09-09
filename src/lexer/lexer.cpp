#include "sbom_dsl/lexer/lexer.hpp"
#include <cctype>

namespace sbom_dsl {

Lexer::Lexer(std::string_view source, std::string filename, DiagnosticEngine& diag)
    : source_(source), filename_(std::move(filename)), diag_(diag) {}

char Lexer::peek() const {
    if (is_at_end()) return '\0';
    return source_[cursor_];
}

char Lexer::peek_next() const {
    if (cursor_ + 1 >= source_.size()) return '\0';
    return source_[cursor_ + 1];
}

char Lexer::advance() {
    char c = source_[cursor_++];
    if (c == '\n') {
        ++line_;
        column_ = 1;
        line_start_ = cursor_;
    } else {
        ++column_;
    }
    return c;
}

bool Lexer::match(char expected) {
    if (is_at_end() || source_[cursor_] != expected) {
        return false;
    }
    advance();
    return true;
}

bool Lexer::is_at_end() const {
    return cursor_ >= source_.size();
}

SourceLocation Lexer::current_location() const {
    return SourceLocation{filename_, line_, column_, cursor_};
}

std::string Lexer::current_line_text() const {
    size_t end = source_.find('\n', line_start_);
    if (end == std::string_view::npos) {
        end = source_.size();
    }
    return std::string(source_.substr(line_start_, end - line_start_));
}

void Lexer::skip_whitespace_and_comments() {
    while (!is_at_end()) {
        char c = peek();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            advance();
        } else if (c == '-' && peek_next() == '-') {
            // SQL-style single-line comment: -- ...
            while (!is_at_end() && peek() != '\n') {
                advance();
            }
        } else if (c == '/' && peek_next() == '/') {
            // C++-style single-line comment: // ...
            while (!is_at_end() && peek() != '\n') {
                advance();
            }
        } else if (c == '/' && peek_next() == '*') {
            // Block comment: /* ... */
            advance(); // consume '/'
            advance(); // consume '*'
            SourceLocation comment_start = current_location();
            bool closed = false;
            while (!is_at_end()) {
                if (peek() == '*' && peek_next() == '/') {
                    advance(); // '*'
                    advance(); // '/'
                    closed = true;
                    break;
                }
                advance();
            }
            if (!closed) {
                diag_.error(comment_start, "Unterminated block comment", current_line_text());
                return;
            }
        } else {
            break;
        }
    }
}

Token Lexer::scan_string(char quote_char) {
    SourceLocation loc = current_location();
    advance(); // Consume opening quote

    std::string value;
    bool closed = false;

    while (!is_at_end()) {
        char c = peek();
        if (c == quote_char) {
            advance();
            closed = true;
            break;
        } else if (c == '\\') {
            advance();
            if (is_at_end()) {
                break;
            }
            char escaped = advance();
            switch (escaped) {
                case 'n': value += '\n'; break;
                case 't': value += '\t'; break;
                case 'r': value += '\r'; break;
                case '\\': value += '\\'; break;
                case '\'': value += '\''; break;
                case '"': value += '"'; break;
                default: value += escaped; break;
            }
        } else if (c == '\n') {
            // Multiline strings are allowed or flag error? Let's allow and advance
            value += advance();
        } else {
            value += advance();
        }
    }

    if (!closed) {
        diag_.error(loc, "Unterminated string literal", current_line_text());
        return Token{TokenType::Invalid, value, loc};
    }

    return Token{TokenType::StringLiteral, value, loc};
}

Token Lexer::scan_number() {
    SourceLocation loc = current_location();
    size_t start = cursor_;
    bool is_float = false;

    while (!is_at_end() && std::isdigit(static_cast<unsigned char>(peek()))) {
        advance();
    }

    if (peek() == '.' && std::isdigit(static_cast<unsigned char>(peek_next()))) {
        is_float = true;
        advance(); // consume '.'
        while (!is_at_end() && std::isdigit(static_cast<unsigned char>(peek()))) {
            advance();
        }
    }

    std::string lexeme(source_.substr(start, cursor_ - start));
    TokenType type = is_float ? TokenType::FloatLiteral : TokenType::IntegerLiteral;
    return Token{type, lexeme, loc};
}

Token Lexer::scan_identifier_or_keyword() {
    SourceLocation loc = current_location();
    size_t start = cursor_;

    while (!is_at_end()) {
        char c = peek();
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-') {
            advance();
        } else {
            break;
        }
    }

    std::string lexeme(source_.substr(start, cursor_ - start));
    auto kw = lookup_keyword(lexeme);
    if (kw.has_value()) {
        return Token{kw.value(), lexeme, loc};
    }

    return Token{TokenType::Identifier, lexeme, loc};
}

Token Lexer::scan_token() {
    skip_whitespace_and_comments();

    if (is_at_end()) {
        return Token{TokenType::EndOfFile, "", current_location()};
    }

    SourceLocation loc = current_location();
    char c = peek();

    // String literals ('...' or "...")
    if (c == '"' || c == '\'') {
        return scan_string(c);
    }

    // Number literals
    if (std::isdigit(static_cast<unsigned char>(c))) {
        return scan_number();
    }

    // Identifiers and keywords
    if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
        return scan_identifier_or_keyword();
    }

    // Single / Double character operators and symbols
    advance(); // Consume the character
    switch (c) {
        case '*': return Token{TokenType::Star, "*", loc};
        case ',': return Token{TokenType::Comma, ",", loc};
        case '.': return Token{TokenType::Dot, ".", loc};
        case ';': return Token{TokenType::Semicolon, ";", loc};
        case '(': return Token{TokenType::LParen, "(", loc};
        case ')': return Token{TokenType::RParen, ")", loc};

        case '=': return Token{TokenType::Equal, "=", loc};
        case '!':
            if (match('=')) {
                return Token{TokenType::NotEqual, "!=", loc};
            }
            diag_.error(loc, "Unexpected character '!'. Did you mean '!='?", current_line_text());
            return Token{TokenType::Invalid, "!", loc};

        case '<':
            if (match('=')) {
                return Token{TokenType::LessEqual, "<=", loc};
            }
            return Token{TokenType::Less, "<", loc};

        case '>':
            if (match('=')) {
                return Token{TokenType::GreaterEqual, ">=", loc};
            }
            return Token{TokenType::Greater, ">", loc};

        default: {
            std::string s(1, c);
            diag_.error(loc, "Unexpected character '" + s + "'", current_line_text());
            return Token{TokenType::Invalid, s, loc};
        }
    }
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    while (!is_at_end()) {
        Token token = scan_token();
        if (token.type == TokenType::EndOfFile) {
            tokens.push_back(token);
            break;
        }
        tokens.push_back(token);
    }
    if (tokens.empty() || tokens.back().type != TokenType::EndOfFile) {
        tokens.push_back(Token{TokenType::EndOfFile, "", current_location()});
    }
    return tokens;
}

} // namespace sbom_dsl
