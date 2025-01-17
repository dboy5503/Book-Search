import User from '../models/User';
import { signToken } from '../services/auth';
import { IResolvers } from '@graphql-tools/utils';
import { AuthenticationError } from 'apollo-server-express';


const resolvers: IResolvers = {
    Query: {
        me: async (_parent, _args, context) => {
            if (context.user) {
                return User.findOne({ _id: context.user._id });
            }
            throw new AuthenticationError('You need to be logged in!');
        },
        user: async (_parent, { id, username }) => {
            return User.findOne({
                $or: [{ _id: id }, { username }],
            });
        },
    },
    Mutation: {
        createUser: async (_parent, args) => {
            const user = await User.create(args);
            const token = signToken(user.username, user.password, user._id);
            return { token, user };
        },
        login: async (_parent, { username, email, password }) => {
            const user = await User.findOne({ $or: [{ username }, { email }] });
            if (!user) {
                throw new AuthenticationError("Can't find this user");
            }

            const correctPw = await user.isCorrectPassword(password);

            if (!correctPw) {
                throw new AuthenticationError('Wrong password!');
            }
            const token = signToken(user.username, user.password, user._id);
            return { token, user };
        },
        saveBook: async (_parent, args, context) => {
            if (context.user) {
                const updatedUser = await User.findOneAndUpdate(
                    { _id: context.user._id },
                    { $addToSet: { savedBooks: args.book } },
                    { new: true, runValidators: true }
                );
                return updatedUser;
            }
            throw new AuthenticationError('You need to be logged in!');
        },
        deleteBook: async (_parent, { bookId }, context) => {
            if (context.user) {
                const updatedUser = await User.findOneAndUpdate(
                    { _id: context.user._id },
                    { $pull: { savedBooks: { bookId } } },
                    { new: true }
                );
                return updatedUser;
            }
            throw new AuthenticationError('You need to be logged in!');
        },
    },
};

export default resolvers;