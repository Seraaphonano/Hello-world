module Unfold where
import Data.List (unfoldr)
import Prelude hiding (take, zip, (++))


-- take n _ | n <= 0 = []
-- take _ [] = []
-- take n (x : xs) = x : take (n -1) xs
take :: Int -> [a] -> [a]
take n xs = unfoldr (\t -> case t of 
  (_, 0)  -> Nothing
  ([], n) -> Nothing
  (x:xs,n) -> Just (x, (xs, n-1)) ) (xs,n)


zip :: [a] -> [b] -> [(a, b)]
zip as bs = unfoldr (\t -> case t of 
  ([], _)   -> Nothing
  (_, [])   -> Nothing
  (a:as, b:bs) -> Just ((a,b), (as, bs) )) (as, bs)
-- zip [] _bs = []
-- zip _as [] = []
-- zip (a : as) (b : bs) = (a, b) : zip as bs
fibs :: [Integer]
fibs = unfoldr (\(a, b) -> Just (b, (b, a+b))) (0,1)
-- fibs :: [Integer]
-- fibs = 1 ： fibs

primes :: [Integer]
primes = unfoldr f [2..]
  where
 --   f1 :: [Integer] -> Maybe(Integer, [Integer])
    f (x:xs) = Just(x, [n | n <- xs, n `mod` x /=0])

apo :: (t -> Either [a] (a, t)) -> t -> [a]
apo rep seed = produce seed
  where
    produce seed = case rep seed of
      Left l -> l
      Right (a, ns) -> a : produce ns


unfoldrApo :: (t -> Maybe (a, t)) -> t -> [a]
unfoldrApo f1 seed = apo f2 seed 
  where 
    f2 x = case f1 x of
      Nothing -> Left []
      Just x -> Right x


(++) :: [a] -> [a] -> [a]
x ++ y = apo f(x,y)
  where
--    f :: ([a],[a]) -> Either [a] (a,([a],[a]))
    f([],y) = Left y
    f(x:xs, y) = Right(x ,(xs, y))  

insert :: (Ord a) => a -> [a] -> [a]
insert n xs = apo ins(n, xs)
  where 
    ins(n, []) = Left [n]
    ins(n, x:ys)
      | n<=x = Left (n:x:ys)
      | otherwise = Right (x, (n, ys))
