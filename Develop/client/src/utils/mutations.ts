import { gql } from '@apollo/client';

export const LOGIN_USER = gql`
    mutation loginUser($input: LoginInput) {
        login(input: $input) {
            token
            user {
                _id
                username
            }
        }
    }
`;

export const ADD_USER = gql`
    mutation addUser($input: UserInput) {
        addUser(input: $input) {
            token
            user {
                _id
                username
            }
        }
    }
`;

export const SAVE_BOOK = gql`
    mutation saveBook($book: BookInput) {
        saveBook(book: $book) {
            _id
            username
            savedBooks {
                bookId
                authors
                description
                title
                image
                link
            }
        }
    }
`;

export const REMOVE_BOOK = gql`
    mutation removeBook($bookId: ID!) {
        removeBook(bookId: $bookId) {
            _id
            username
            savedBooks {
            bookId
            authors
            description
            title
            image
            link
            }
        }
        }
    `;